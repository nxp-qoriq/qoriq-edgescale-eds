/*
 **********************************
 *
 * Copyright 2017 NXP
 *
 **********************************
 */
package main

import (
	"./pkg/openssl"
	"./pkg/securekey"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/laurentluce/est-client-go"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Config struct {
	SecureLevel *int
	Version     string
}

type Token struct {
	E_Token string `json:"e_token"`
}

type Challenge struct {
	Device_ID string `json:"device_id"`
	Challenge string `json:"challenge"`
}

var cfg Config

func InitFlags() {
	cfg.SecureLevel = flag.Int("s", 1, "security level 0-2")
	flag.Parse()
}

func CreateCsr(priv crypto.PrivateKey, commonName string, country string, state string, city string, organization string, organizationalUnit string, emailAddress string) ([]byte, error) {
	random := rand.Reader
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         commonName,
			Country:            []string{country},
			Province:           []string{state},
			Locality:           []string{city},
			Organization:       []string{organization},
			OrganizationalUnit: []string{organizationalUnit},
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		//SignatureAlgorithm: x509.ECDSAWithSHA256,
		EmailAddresses: []string{emailAddress},
	}

	csrBytes, err := x509.CreateCertificateRequest(random, &template, priv)
	if err != nil {
		return nil, err
	}
	block := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}
	certPem := pem.EncodeToMemory(&block)

	return certPem, nil
}

func LoadMfKey(key string) (crypto.PrivateKey, error) {
	data, err := ioutil.ReadFile(key)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("No valid key found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		privkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err == nil {
			size := privkey.N.BitLen()
			cmd := fmt.Sprintf("sobj_app  -L -l %s | grep handle |awk '{print $4}' | xargs -i sobj_app -R -h {}", key)
			exec.Command("bash", "-c", cmd).Run()
			cmd = fmt.Sprintf("sobj_app -C -f %s -k rsa -o pair -s %d -l %s -i 0 -w %s", key, size, key, key)
			exec.Command("bash", "-c", cmd).Run()
		} else {
			id, err := openssl.ParseSobjPrivateKey(block.Bytes)
			if err != nil {
				fmt.Println("No valid key found")
				os.Exit(1)
			}
			fmt.Println("Load sobj private key, ID:", id)
		}
		eng := openssl.Sobj_Init()
		priv, _ := eng.Sobj_Loadkey(key)
		return priv, nil
	default:
		return nil, fmt.Errorf("Unsupported key type %q", block.Type)
	}

	return nil, nil
}

func Get_device_fqdn(device_id string) (string, error) {
	type DeviceModel struct {
		Model    string `json:"model"`
		Type     string `json:"type"`
		Platform string `json:"platform"`
		Vendor   string `json:"vendor"`
	}

	url := fmt.Sprintf("https://api.edgescale.org/v1/devices/type?uid=%s", device_id)
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Accept", fmt.Sprintf("application/json; version=%s", cfg.Version))
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	bs, err := ioutil.ReadAll(resp.Body)

	var m DeviceModel
	json.Unmarshal(bs, &m)

	device_fqdn := fmt.Sprintf("%s.%s.%s.%s.%s", device_id, m.Model, m.Type, m.Platform, m.Vendor)
	return device_fqdn, err

}

func ParseCertificate(b []byte) (*int64, *string, error) {
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, nil, errors.New("invalid memory address or nil pointer dereference")
	}
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, nil, err
	}
	timeNow := time.Now()
	expires := int64(cert.NotAfter.Sub(timeNow).Hours()) / 24
	return &expires, &cert.Subject.CommonName, nil
}

func Sha256Sum(msg string) []byte {
	h := sha256.New()
	h.Write([]byte(msg))
	d := h.Sum(nil)
	return d
}

func Get_pin() string {
	return "secure"
}

func phase2() (string, string) {
	var (
		response  string
		e_token   string
		device_id string
		fuid      string
	)

	b, err := ioutil.ReadFile("/data/device-id.ini")
	if err != nil {
		fmt.Println("No FUID found in MMC card")
	}
	fuid = strings.Trim(string(b), "\n")

	buf := make([]byte, 5)
	rand.Read(buf)
	msg := hex.EncodeToString(buf)

	mf_key := "/data/private_keys/mf-private.pem"

	switch level := *cfg.SecureLevel; {
	case level < 1:
		b, _ := ioutil.ReadFile(mf_key)
		block, _ := pem.Decode(b)
		priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
		signed, err := priv.Sign(rand.Reader, Sha256Sum(msg), crypto.SHA256)
		response, device_id = Get_challenge(signed, fuid, msg)
		signed, err = priv.Sign(rand.Reader, Sha256Sum(response), crypto.SHA256)
		e_token = Get_EToken(device_id, signed)
		if err != nil {
			os.Exit(1)
		}

	case level == 1:
		key, err := LoadMfKey(mf_key)
		if err != nil {
			fmt.Println("No Sobj privatekey Found")
			os.Exit(1)
		}
		priv := key.(crypto.Signer)
		signed, err := priv.Sign(rand.Reader, Sha256Sum(msg), crypto.SHA256)
		response, device_id = Get_challenge(signed, fuid, msg)
		signed, err = priv.Sign(rand.Reader, Sha256Sum(response), crypto.SHA256)
		e_token = Get_EToken(device_id, signed)
		if err != nil {
			os.Exit(1)
		}
	case level == 2:
		fuid, _ = sk.SK_fuid()
		signed, err := sk.SK_sign(msg)
		response, device_id = Get_challenge(signed, fuid, msg)
		signed, err = sk.SK_sign(response)
		e_token = Get_EToken(device_id, signed)
		if err != nil {
			os.Exit(1)
		}
	}

	return device_id, e_token
}

func Get_EToken(device_id string, signed interface{}) string {
	var sig string
	switch s := signed.(type) {
	case []byte:
		sig = base64.StdEncoding.EncodeToString(s)
	case string:
		sig = s
	}
	url := "https://api.edgescale.org/v1/enroll/token"

	values := map[string]string{"sig": sig, "device_id": device_id}
	jsonValue, _ := json.Marshal(values)

	contentType := fmt.Sprintf("application/json; version=%s", cfg.Version)
	resp, err := http.Post(url, contentType, bytes.NewBuffer(jsonValue))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	bs, _ := ioutil.ReadAll(resp.Body)

	var t Token
	json.Unmarshal(bs, &t)
	if t.E_Token == "" {
		fmt.Println("No valid e_token")
		os.Exit(1)
	}

	return t.E_Token

}

func Get_challenge(signed interface{}, fuid string, msg string) (string, string) {
	var sig string
	switch s := signed.(type) {
	case []byte:
		sig = base64.StdEncoding.EncodeToString(s)
	case string:
		sig = s
	}
	url := "https://api.edgescale.org/v1/enroll/challenge"

	values := map[string]string{"fuid": fuid, "sig": sig, "msg": msg}
	jsonValue, _ := json.Marshal(values)

	contentType := fmt.Sprintf("application/json; version=%s", cfg.Version)
	resp, err := http.Post(url, contentType, bytes.NewBuffer(jsonValue))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	bs, _ := ioutil.ReadAll(resp.Body)
	var c Challenge
	err = json.Unmarshal(bs, &c)

	if c.Challenge == "" {
		fmt.Println("No valid challenge code")
		os.Exit(1)
	}

	pin := Get_pin()
	response := hex.EncodeToString(Sha256Sum(pin)) + c.Challenge

	return response, c.Device_ID
}

func main() {
	var err error
	InitFlags()

	b, _ := ioutil.ReadFile("/etc/edgescale-version")
	cfg.Version = strings.Trim(string(b), "\n")

	cmd := "dd  if=/dev/mmcblk0 of=/run/secure.bin  skip=62 bs=1M count=1 && sync && mount -o loop /run/secure.bin /data/"
	err = exec.Command("bash", "-c", cmd).Run()
	if err != nil {
		cmd = "fsck.ext2 -yf /run/secure.bin || mkfs.ext2 /run/secure.bin && mount /run/secure.bin /data && mkdir -p /data/{certs,private_keys}"
		err = exec.Command("bash", "-c", cmd).Run()
	}

	dev_cert := fmt.Sprintf("/data/certs/edgescale.pem")
	dev_key := fmt.Sprintf("/data/private_keys/edgescale.key")

	b, err = ioutil.ReadFile(dev_cert)
	if err != nil {
		fmt.Println("No valid certificate found, starting 3 Phases Certificate Enrollment")
	} else {
		expires, CommonName, err := ParseCertificate(b)
		if err != nil {
			fmt.Println("No valid certificate found, starting 3 Phases Certificate Enrollment")
		} else if *expires > 1 {
			fmt.Printf("edgescale cert expires: %v days, skip certificate Enrollment\n", *expires)
			cmd = fmt.Sprintf("echo %s > /etc/hostname && hostname -F /etc/hostname", *CommonName)
			exec.Command("bash", "-c", cmd).Run()
			os.Exit(0)
		}
	}

	fmt.Println("starting Phase1")
	cmd = "/usr/local/bin/bootstrap-enroll"
	err = exec.Command("bash", "-c", cmd).Run()
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("starting Phase2")
	device_id, e_token := phase2()
	if err != nil {
		panic(err)
	}

	country := "CN"
	state := "China"
	city := "Beijing"
	organization := ""
	organizationalUnit := ""
	emailAddress := ""

	serverCA, _ := ioutil.ReadFile("/tmp/rootCA.pem")

	//E-EST certs
	fmt.Println("starting Phase3")
	client := est.Client{
		URLPrefix:  "https://int.e-est.edgescale.org",
		Username:   device_id,
		Password:   e_token,
		ServerCert: serverCA}

	caCerts, _ := client.CaCerts()

	b_cert, _ := ioutil.ReadFile("/tmp/bootstrap.pem")
	b_priv, _ := ioutil.ReadFile("/tmp/bootstrap.key")

	var device_fqdn string
	device_fqdn, err = Get_device_fqdn(device_id)

	var (
		priv []byte
		csr  []byte
	)

	switch level := *cfg.SecureLevel; {

	case level < 1:
		priv, csr, _ = est.CreateCsr(device_fqdn, country, state, city, organization, organizationalUnit, emailAddress)
		ioutil.WriteFile(dev_key, priv, 0644)
	case level < 3:
		eng := openssl.Sobj_Init()
		key := eng.Sobj_KeyGen(dev_key, 1)
		csr, _ = CreateCsr(key, device_fqdn, country, state, city, organization, organizationalUnit, emailAddress)
	}

	fmt.Printf("Starting E-EST certificate Enrollment\n")
	cert, err := client.SimpleReenroll(csr, b_cert, b_priv)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	ioutil.WriteFile("/data/certs/estrootca.pem", caCerts, 0644)
	ioutil.WriteFile(dev_cert, cert, 0644)

	cmd = fmt.Sprintf("echo %s > /etc/hostname && hostname -F /etc/hostname", device_fqdn)
	exec.Command("bash", "-c", cmd).Run()

	cmd = "sync && dd if=/run/secure.bin of=/dev/mmcblk0 seek=62 bs=1M"
	exec.Command("bash", "-c", cmd).Run()
	fmt.Printf("set Hostname to %s\n", device_fqdn)
}
