/*
 **********************************
 *
 * Copyright 2017 NXP
 *
 **********************************
 */

package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/laurentluce/est-client-go"
	"io/ioutil"
	"os/exec"
	"time"
)

func parse(path string) ([]byte, *float64, *string, error) {
	block, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	p, _ := pem.Decode(block)
	if p == nil {
		return nil, nil, nil, errors.New("No valid certificate")
	}

	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	timeNow := time.Now()
	expires := float64(cert.NotAfter.Sub(timeNow).Hours()) / 24
	return block, &(expires), &(cert.Subject.CommonName), nil
}

func main() {
	var cert []byte
	var key []byte
	var expires *float64
	var device_id *string

	cmd := "mkdir -p /etc/ssl/private/edgescale/{certs,private_keys}"
	exec.Command("bash", "-c", cmd).Output()

	cert_path := fmt.Sprintf("/etc/ssl/private/edgescale/certs/edgescale.pem")
	key_path := fmt.Sprintf("/etc/ssl/private/edgescale/private_keys/edgescale.key")

	bcert_path := fmt.Sprintf("/etc/ssl/private/edgescale/certs/edgescale-bootstrap.pem")
	bkey_path := fmt.Sprintf("/etc/ssl/private/edgescale/private_keys/edgescale-bootstrap.key")

	cert, expires, device_id, err := parse(cert_path)
	if err != nil {
		fmt.Println("No valid certificate found, starting Certificate Enrollment")
		key, err = ioutil.ReadFile(bkey_path)
		if err != nil {
			fmt.Println("no valid bootstrap certificate private key, please Enroll new bootstrap certificate from Edgescale")
			return
		}
		cert, expires, device_id, err = parse(bcert_path)
		if err != nil {
			fmt.Println("No valid bootstrap certificate, please Enroll new bootstrap certificate from Edgescale")
			return
		}
		if *expires <= 0 {
			fmt.Println("expired bootstrap certificate, Please Enroll new bootstrap certificate form Edgescale")
			return
		}
	} else {
		if err != nil {
			fmt.Println(err)
		}
		if *expires > 1 {
			fmt.Printf("certificate expires: %v days, skip certificate Enrollment\n", *expires)
			cmd = fmt.Sprintf("echo %s > /etc/hostname && hostname -F /etc/hostname", *device_id)
			exec.Command("bash", "-c", cmd).Output()
			fmt.Printf("set Hostname to %s\n", *device_id)
			return
		}
		key, err = ioutil.ReadFile(key_path)
		if err != nil {
			fmt.Println("no valid certificate private key, please Enroll new bootstrap certificate from Edgescale")
			return
		}
	}

	fmt.Printf("DeviceID: %s\n", *device_id)

	serverCA, err := ioutil.ReadFile("/etc/ssl/private/edgescale/certs/estrootca.pem")
	if err != nil {
		fmt.Println("No RootCA found, please download RootCA from Edgescale")
		return
	}

	commonName := *device_id
	country := "CN"
	state := "China"
	city := "Beijing"
	organization := "Edgescale.org"
	organizationalUnit := "NXP EdgeScale Services"
	emailAddress := "admin@edgescale.org"

	client := est.Client{
		URLPrefix:  "https://int.e-est.edgescale.org",
		ServerCert: serverCA,
	}

	priv, csr, _ := est.CreateCsr(commonName, country, state, city, organization, organizationalUnit, emailAddress)
	fmt.Printf("Starting E-EST certificate Enrollment\n")
	new_cert, err := client.SimpleReenroll(csr, cert, key)
	if err != nil {
		fmt.Println(err)
	}

	ioutil.WriteFile(cert_path, new_cert, 0644)
	ioutil.WriteFile(key_path, priv, 0644)

	cmd = fmt.Sprintf("echo %s > /etc/hostname && hostname -F /etc/hostname", *device_id)
	exec.Command("bash", "-c", cmd).Output()

	fmt.Printf("set Hostname to %s\n", *device_id)
}
