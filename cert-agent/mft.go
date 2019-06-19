/*
 **********************************
 *
 * Copyright 2017-2019 NXP
 *
 **********************************
 */

package main

import (
	"./pkg/securekey"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	yaml "gopkg.in/yaml.v2"
	"io/ioutil"
	"math/big"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

const (
	letters    = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lettersLen = 16
)

type ESconf struct {
	API string  `yaml:"api"`
	Mft MftConf `yaml:"mft"`
}

type MftConf struct {
	KeyID string `yaml:"keyID"`
	Key   string `yaml:"key"`
	OemID string `yaml:"oemID"`
}

func Mft() error {
	var (
		cmd   string
		err   error
		fuid  string
		oemID string
	)
	data, _ := ioutil.ReadFile(*cfg.Config)
	args, _ := ioutil.ReadFile("/proc/cmdline")
	yaml.Unmarshal(data, &esconf)
	parseCommandLine(string(args), &esconf)

	if esconf.Mft.Key == "" {
		return nil
	}

	cmd = fmt.Sprintf("dd if=%s of=/run/secure.bin skip=%d bs=1M count=1 && e2label /run/secure.bin | grep MFT", *cfg.Dev, *cfg.DevAddr)
	err = exec.Command("bash", "-c", cmd).Run()
	if err == nil {
		return nil
	}

	fmt.Println("Starting MFT service")

	mac := hmac.New(sha256.New, []byte(esconf.Mft.Key))

	if fuid, _ = sk.SK_fuid(); fuid == "0000000000000000" {
		fuid = getRandom(16)
	}
	if oemID, _ = sk.SK_oemid(); oemID == "0000000000000000000000000000000000000000" {
		oemID = esconf.Mft.OemID
	}
	deviceID := fmt.Sprintf("%s:%s", fuid, oemID)
	mac.Write([]byte(fuid))
	sig := hex.EncodeToString(mac.Sum(nil))

	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	block := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	privPem := pem.EncodeToMemory(&block)

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(priv.Public())
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509EncodedPub,
	})
	skPub := base64.StdEncoding.EncodeToString(pemEncodedPub)
	skHash := sha1Sum(priv.PublicKey.N.Bytes())

	retry(*cfg.Retry, 5*time.Second, func() error {
		return deviceReg(fuid, oemID, sig, esconf.Mft.KeyID, skPub, skHash)
	})

	cmd = "dd if=/dev/zero of=/tmp/secure.bin bs=1M count=1 && mkfs.ext2 -L MFT /tmp/secure.bin && mkdir -p /tmp/data && mount -o loop /tmp/secure.bin /tmp/data"
	exec.Command("bash", "-c", cmd).Run()

	cmd = "mkdir -p /tmp/data/certs && mkdir /tmp/data/private_keys"
	exec.Command("bash", "-c", cmd).Run()

	ioutil.WriteFile("/tmp/data/device-id.ini", []byte(deviceID), 0644)
	ioutil.WriteFile("/tmp/data/private_keys/mf-private.pem", privPem, 0644)

	exec.Command("bash", "-c", "sync").Run()
	exec.Command("bash", "-c", "umount /tmp/data").Run()
	exec.Command("bash", "-c", fmt.Sprintf("dd if=/tmp/secure.bin of=%s bs=1M seek=%d conv=sync", *cfg.Dev, *cfg.DevAddr)).Run()
	return err
}

func sha1Sum(b []byte) string {
	h := sha1.New()
	h.Write([]byte(b))
	return hex.EncodeToString(h.Sum(nil))
}

func deviceReg(fuid string, oemID string, sig string, keyID string, skPUB string, skHash string) error {
	type retStatus struct {
		Message string `json:"message"`
		Status  string `json:"status"`
	}
	url := fmt.Sprintf("%s/mft/devices", esconf.API)

	values := map[string]string{"sig": sig, "fuid": fuid, "oem_id": oemID, "key_id": keyID, "sk_pub": skPUB, "sk_hash": skHash}
	jsonValue, _ := json.Marshal(values)

	contentType := fmt.Sprintf("application/json; version=%s", cfg.Version)
	resp, err := http.Post(url, contentType, bytes.NewBuffer(jsonValue))
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer resp.Body.Close()
	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return err
	}

	var r retStatus
	json.Unmarshal(bs, &r)
	if r.Status != "success" {
		fmt.Println("Device Create Error:", r.Message)
		return errors.New(r.Message)
	}
	return nil
}

func getRandom(n int) string {
	charsLength := big.NewInt(int64(lettersLen))
	b := make([]byte, n)
	for i := range b {
		r, _ := rand.Int(rand.Reader, charsLength)
		b[i] = letters[r.Int64()]
	}
	return string(b)
}

func parseCommandLine(command string, conf *ESconf) error {
	args := strings.Split(command, " ")
	for _, arg := range args {
		if strings.HasPrefix(arg, "ES-KEY-ID") {
			conf.Mft.KeyID = strings.Split(arg, "=")[1]
		}
		if strings.HasPrefix(arg, "ES-KEY") {
			conf.Mft.Key = strings.Split(arg, "=")[1]
		}
	}
	return nil
}
