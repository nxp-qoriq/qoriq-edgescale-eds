/*
 **********************************
 *
 * Copyright 2017-2018 NXP
 *
 **********************************
 */

package main

import (
	"./pkg/config"
	"./pkg/openssl"
	"./pkg/securekey"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
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
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Config struct {
	SecureLevel *int
	Version     string
	URI         string
	APIURI      string `json:"api_uri"`
	ChainURL    string
}

type Token struct {
	E_Token  string `json:"e_token"`
	APIURI   string `json:"api_uri"`
	URI      string `json:"ca_uri"`
	ChainURL string `json:"chain_url"`
}

type Challenge struct {
	Device_ID string `json:"device_id"`
	Challenge string `json:"challenge"`
}

var cfg Config

func InitFlags() {
	cfg.SecureLevel = flag.Int("s", 0, "security level 0-2")
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

	url := fmt.Sprintf("%s/devices/type?uid=%s", cfg.APIURI, device_id)
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
	resp.Body.Close()

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

func phase2() (string, string, string) {
	var (
		response  string
		e_token   string
		device_id string
		fuid      string
		oemID     string
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
		oemID, _ = sk.SK_oemid()
		keyHash, _ := sk.SKPubKeySha1()
		signed, err := sk.SK_sign(msg)
		mp := fmt.Sprintf("%s:%s:%s", fuid, oemID, keyHash)
		response, device_id = Get_challenge(signed, mp, msg)
		signed, err = sk.SK_sign(response)
		e_token = Get_EToken(device_id, signed)
		if err != nil {
			os.Exit(1)
		}
	}

	return device_id, e_token, cfg.URI
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
	resp.Body.Close()
	cfg.URI = t.URI
	cfg.ChainURL = t.ChainURL
	cfg.APIURI = t.APIURI

	return t.E_Token

}

func Get_challenge(signed interface{}, mp string, msg string) (string, string) {
	var sig string
	switch s := signed.(type) {
	case []byte:
		sig = base64.StdEncoding.EncodeToString(s)
	case string:
		sig = s
	}
	url := "https://api.edgescale.org/v1/enroll/challenge"

	var values map[string]string
	switch i := strings.Split(mp, ":"); len(i) {
	case 1:
		values = map[string]string{"fuid": i[0], "sig": sig, "msg": msg}
	case 2:
		values = map[string]string{"fuid": i[0], "oem_id": i[1], "sig": sig, "msg": msg}
	case 3:
		values = map[string]string{"fuid": i[0], "oem_id": i[1], "key_hash": i[2], "sig": sig, "msg": msg}
	}

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
	resp.Body.Close()

	return response, c.Device_ID
}

func getEdgeScaleConfig(deviceID string) {
	certPEMBlock, _ := ioutil.ReadFile("/data/certs/edgescale.pem")
	keyPEMBlock, _ := ioutil.ReadFile("/data/private_keys/edgescale.key")
	cert, err := openssl.X509KeyPair(certPEMBlock, keyPEMBlock, "/data/private_keys/edgescale.key")
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	serverCert, _ := ioutil.ReadFile("/data/certs/rootCA.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(serverCert)
	tlsConfig.RootCAs = caCertPool
	if cfg.URI == "" {
		b, _ := pem.Decode(certPEMBlock)
		c, _ := x509.ParseCertificate(b.Bytes)
		u, _ := url.Parse(c.OCSPServer[0])
		cfg.URI = fmt.Sprintf("https://%s", u.Host)
	}

	url := fmt.Sprintf("%s/.well-known/jwt", cfg.URI)
	tr := &http.Transport{
		TLSClientConfig: &tlsConfig,
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Println(err)
	}
	bs, _ := ioutil.ReadAll(resp.Body)
	if resp.Status == "401 Unauthorized" {
		fmt.Println("Get jwt token: ", resp.Status)
		return
	}
	accessToken := string(bs)
	ioutil.WriteFile("/data/.edgescale.cred", bs, 0400)
	resp.Body.Close()

	url = fmt.Sprintf("https://api.edgescale.org/v1/devices/%s/endpoints", deviceID)
	client = &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Accept", fmt.Sprintf("application/json; version=%s", cfg.Version))
	req.Header.Add("access-token", accessToken)
	resp, err = client.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	bs, err = ioutil.ReadAll(resp.Body)
	if resp.Status == "401 Unauthorized" {
		fmt.Println("Get EdgeScale endpoint: ", resp.Status)
		fmt.Println(string(bs))
		return
	}
	resp.Body.Close()
	jsonconfig.Json2env("es", bs, "/data/config.env")
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
			getEdgeScaleConfig(*CommonName)
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
	device_id, e_token, uri := phase2()
	if err != nil {
		panic(err)
	}

	country := "CN"
	state := "China"
	city := "Beijing"
	organization := ""
	organizationalUnit := ""
	emailAddress := ""

	fmt.Println("Download EST Server RootCA")
	cmd = fmt.Sprintf("curl %s -o /data/certs/rootCA.pem", cfg.ChainURL)
	exec.Command("bash", "-c", cmd).Output()
	serverCA, _ := ioutil.ReadFile("/data/certs/rootCA.pem")

	//E-EST certs
	fmt.Println("starting Phase3")
	client := est.Client{
		URLPrefix:  uri,
		Username:   device_id,
		Password:   e_token,
		ServerCert: serverCA}

	caCerts, _ := client.CaCerts()

	b_cert, err := ioutil.ReadFile("/tmp/bootstrap.pem")
	b_priv, err := ioutil.ReadFile("/tmp/bootstrap.key")

	var device_fqdn string
	device_fqdn, err = Get_device_fqdn(device_id)

	var (
		priv []byte
		csr  []byte
	)

	switch level := *cfg.SecureLevel; {

	case level < 1:
		priv, csr, _ = est.CreateCsr(device_fqdn, country, state, city, organization, organizationalUnit, emailAddress)
		ioutil.WriteFile(dev_key, priv, 0400)
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

	ioutil.WriteFile("/data/certs/estrootca.pem", caCerts, 0400)
	ioutil.WriteFile(dev_cert, cert, 0400)

	cmd = fmt.Sprintf("echo %s > /etc/hostname && hostname -F /etc/hostname", device_fqdn)
	exec.Command("bash", "-c", cmd).Run()

	cmd = "sync && dd if=/run/secure.bin of=/dev/mmcblk0 seek=62 bs=1M"
	exec.Command("bash", "-c", cmd).Run()
	fmt.Printf("set Hostname to %s\n", device_fqdn)
	getEdgeScaleConfig(device_id)
}
