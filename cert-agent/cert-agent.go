/*
 **********************************
 *
 * Copyright 2017 NXP
 *
 **********************************
 */
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/laurentluce/est-client-go"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"time"
)

type Token struct {
	E_Token string `json:"e_token"`
}

type Challenge struct {
	Device_ID string `json:"device_id"`
	Challenge string `json:"challenge"`
}

func Get_device_fqdn(device_id string) (string, error) {
	type DeviceModel struct {
		Model    string `json:"model"`
		Type     string `json:"type"`
		Platform string `json:"platform"`
		Vendor   string `json:"vendor"`
	}

	url := fmt.Sprintf("https://api.edgescale.org/public/devices/type?uid=%s", device_id)
	resp, err := http.Get(url)
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
	)

	fuid, _ := os.Hostname()
	buf := make([]byte, 5)
	rand.Read(buf)
	msg := hex.EncodeToString(buf)

	mf_key := "/etc/ssl/private/edgescale/private_keys/mf-private.pem"

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
	url := "https://api.edgescale.org/secure/enroll/token"

	values := map[string]string{"sig": sig, "device_id": device_id}
	jsonValue, _ := json.Marshal(values)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonValue))
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
	url := "https://api.edgescale.org/secure/enroll/challenge"

	values := map[string]string{"fuid": fuid, "sig": sig, "msg": msg}
	jsonValue, _ := json.Marshal(values)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonValue))
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
	cmd := "mkdir -p /etc/ssl/private/edgescale/{certs,private_keys}"
	exec.Command("bash", "-c", cmd).Run()

	cmd = "dd  if=/dev/mmcblk0 of=/run/secure.bin  skip=62 bs=1M count=1 && mount -o loop /run/secure.bin /etc/ssl/private/edgescale/"
	err = exec.Command("bash", "-c", cmd).Run()
	if err != nil {
		fmt.Println(err)
	}

	cmd = "hostname -F /etc/ssl/private/edgescale/device-id.ini"
	err = exec.Command("bash", "-c", cmd).Run()

	dev_cert := fmt.Sprintf("/etc/ssl/private/edgescale/certs/edgescale.pem")
	dev_key := fmt.Sprintf("/etc/ssl/private/edgescale/private_keys/edgescale.key")

	b, err := ioutil.ReadFile(dev_cert)
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

	fmt.Printf("starting Phase1\n")
	cmd = "/usr/local/bin/bootstrap-enroll"
	err = exec.Command("bash", "-c", cmd).Run()
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("starting Phase2\n")
	device_id, e_token := phase2()

	country := "CN"
	state := "China"
	city := "Beijing"
	organization := ""
	organizationalUnit := ""
	emailAddress := ""

	serverCA, _ := ioutil.ReadFile("/tmp/rootCA.pem")

	//E-EST certs
	fmt.Printf("starting Phase3\n")
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

	fmt.Println("create PKCS10 request")
	var (
		priv []byte
		csr  []byte
	)
	priv, csr, _ = est.CreateCsr(device_fqdn, country, state, city, organization, organizationalUnit, emailAddress)
	fmt.Printf("Starting E-EST certificate Enrollment\n")
	cert, err := client.SimpleReenroll(csr, b_cert, b_priv)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	ioutil.WriteFile("/etc/ssl/private/edgescale/certs/estrootca.pem", caCerts, 0644)
	ioutil.WriteFile(dev_cert, cert, 0644)
	ioutil.WriteFile(dev_key, priv, 0644)

	cmd = fmt.Sprintf("echo %s > /etc/hostname && hostname -F /etc/hostname", device_fqdn)
	exec.Command("bash", "-c", cmd).Run()

	cmd = "sync && dd if=/run/secure.bin of=/dev/mmcblk0 seek=62 bs=1M"
	exec.Command("bash", "-c", cmd).Run()
	fmt.Printf("set Hostname to %s\n", device_fqdn)
}
