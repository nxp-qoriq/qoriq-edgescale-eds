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
	"github.com/edgeiot/est-client-go"
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
	Config      *string
	URI         *string
	DeviceID    string
	APIURI      string `json:"api_uri"`
	TrustChain  string `json:"trust_chain"`
	Retry       *int
	Dev         *string
	DevAddr     *int
	ReNew       *bool
	Engine      *string
}

type Token struct {
	E_Token    string `json:"e_token"`
	APIURI     string `json:"api_uri"`
	URI        string `json:"ca_uri"`
	TrustChain string `json:"trust_chain"`
	Model      string `json:"device_model"`
	Message    string `json:"message"`
}

type Challenge struct {
	Device_ID string `json:"device_id"`
	Challenge string `json:"challenge"`
	Message   string `json:"message"`
}

var (
	cfg    Config
	esconf ESconf
)

func InitFlags() {
	cfg.SecureLevel = flag.Int("s", 0, "security level 0-2")
	cfg.Retry = flag.Int("retry", 0, "retry, default is always")
	cfg.Dev = flag.String("dev", "/dev/mmcblk0", "certificate storage dev, default is /dev/mmcblk0")
	cfg.DevAddr = flag.Int("devaddr", 62, "secure firmware offset, default is 62")
	cfg.Config = flag.String("config", "/usr/local/edgescale/conf/config.yml", "edgescale config file")
	cfg.ReNew = flag.Bool("renew", false, "renew the certificateRequest")
	cfg.Engine = flag.String("engine", "/usr/lib/aarch64-linux-gnu/openssl-1.0.0/engines/libeng_secure_obj.so", "Use openssl engine, possibly a hardware device, default is nxp secure object engine")
	cfg.URI = flag.String("ca", "", "edgescale ca server, eg: htps://int.b-est.edgescale.org")
	flag.Parse()
}

func retry(attempts int, sleep time.Duration, f func() error) error {
	if err := f(); err != nil {
		if err != nil {
			if attempts == 0 {
				time.Sleep(sleep)
				return retry(attempts, sleep, f)
			}
			if attempts--; attempts > 0 {
				time.Sleep(sleep)
				return retry(attempts, sleep, f)
			}
			return err
		}
	}
	return nil
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
	if err != nil {
		return "", err
	}

	var m DeviceModel
	json.Unmarshal(bs, &m)
	resp.Body.Close()

	device_fqdn := fmt.Sprintf("%s.%s.%s.%s.%s", device_id, m.Model, m.Type, m.Platform, m.Vendor)
	if m.Model == "" {
		return device_fqdn, errors.New("device model not found")
	}

	return device_fqdn, nil

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

func GetOEMID() string {
	if sk.SK_ITS() {
		oemID, _ := sk.SK_oemid()
		return oemID
	}
	b, err := ioutil.ReadFile("/data/device-id.ini")
	if err != nil {
		return ""
	}
	if o := strings.Split(strings.Trim(string(b), "\n"), ":"); len(o) > 1 {
		return o[1]
	}
	return "0000000000000000000000000000000000000000"
}

func phase2() (string, string, string, string) {
	var (
		response     string
		e_token      string
		device_id    string
		device_model string
		fuid         string
		oemID        string
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
		if block == nil {
			fmt.Println("failed to decode mf key")
			os.Exit(1)
		}
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		signed, err := priv.Sign(rand.Reader, Sha256Sum(msg), crypto.SHA256)
		response, device_id = Get_challenge(signed, fuid, msg)
		signed, err = priv.Sign(rand.Reader, Sha256Sum(response), crypto.SHA256)
		e_token, device_model = Get_EToken(device_id, signed)
		if err != nil {
			fmt.Println(err)
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
		e_token, device_model = Get_EToken(device_id, signed)
		if err != nil {
			fmt.Println(err)
		}
	case level == 2:
		fuid, _ = sk.SK_fuid()
		oemID, _ = sk.SK_oemid()
		keyHash, _ := sk.SKPubKeySha1()
		signed, err := sk.SK_sign(msg)
		mp := fmt.Sprintf("%s:%s:%s", fuid, oemID, keyHash)
		response, device_id = Get_challenge(signed, mp, msg)
		signed, err = sk.SK_sign(response)
		e_token, device_model = Get_EToken(device_id, signed)
		if err != nil {
			fmt.Println(err)
		}
	}

	return device_id, device_model, e_token, *cfg.URI
}

func Get_EToken(device_id string, signed interface{}) (string, string) {
	var sig string
	switch s := signed.(type) {
	case []byte:
		sig = base64.StdEncoding.EncodeToString(s)
	case string:
		sig = s
	}
	url := fmt.Sprintf("%s/enroll/token", esconf.API)

	values := map[string]string{"sig": sig, "device_id": device_id}
	jsonValue, _ := json.Marshal(values)

	contentType := fmt.Sprintf("application/json; version=%s", cfg.Version)
	resp, err := http.Post(url, contentType, bytes.NewBuffer(jsonValue))
	if err != nil {
		fmt.Println(err)
		return "", ""
	}
	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return "", ""
	}

	var t Token
	json.Unmarshal(bs, &t)
	if t.E_Token == "" {
		fmt.Println("No valid e_token,", t.Message)
	}
	resp.Body.Close()
	*cfg.URI = t.URI
	cfg.TrustChain = t.TrustChain
	cfg.APIURI = t.APIURI

	return t.E_Token, t.Model

}

func Get_challenge(signed interface{}, mp string, msg string) (string, string) {
	var sig string
	switch s := signed.(type) {
	case []byte:
		sig = base64.StdEncoding.EncodeToString(s)
	case string:
		sig = s
	}
	url := fmt.Sprintf("%s/enroll/challenge", esconf.API)

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
		return "", ""
	}
	bs, _ := ioutil.ReadAll(resp.Body)
	var c Challenge
	err = json.Unmarshal(bs, &c)

	if c.Challenge == "" {
		fmt.Println("No valid challenge code,", c.Message)
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
	if err != nil {
		fmt.Println(err)
		retry(*cfg.Retry, 5*time.Second, func() error {
			return enroll()
		})
		certPEMBlock, _ = ioutil.ReadFile("/data/certs/edgescale.pem")
		keyPEMBlock, _ = ioutil.ReadFile("/data/private_keys/edgescale.key")
		cert, err = openssl.X509KeyPair(certPEMBlock, keyPEMBlock, "/data/private_keys/edgescale.key")
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	serverCert, _ := ioutil.ReadFile("/data/certs/rootCA.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(serverCert)
	tlsConfig.RootCAs = caCertPool
	oemID := GetOEMID()
	nextProto := fmt.Sprintf("x-es-%s-est-ca", oemID)
	tlsConfig.NextProtos = []string{nextProto}
	if *cfg.URI == "" {
		b, _ := pem.Decode(certPEMBlock)
		c, _ := x509.ParseCertificate(b.Bytes)
		u, _ := url.Parse(c.OCSPServer[0])
		*cfg.URI = fmt.Sprintf("https://%s", u.Host)
		cfg.DeviceID = c.Subject.CommonName
	}

	url := fmt.Sprintf("%s/.well-known/jwt", *cfg.URI)
	tr := &http.Transport{
		TLSClientConfig: &tlsConfig,
	}
	client := &http.Client{Transport: tr}
	var accessToken string

	retry(*cfg.Retry, 5*time.Second, func() error {
		resp, err := client.Get(url)
		if err != nil {
			fmt.Println(err)
			if strings.HasSuffix(err.Error(), "remote error: tls: bad certificate") {
				retry(*cfg.Retry, 5*time.Second, func() error {
					return enroll()
				})
				os.Exit(0)
			}
			return err
		}
		bs, _ := ioutil.ReadAll(resp.Body)
		if resp.Status == "401 Unauthorized" {
			fmt.Println("Get jwt token: ", resp.Status)
			return errors.New("401 Unauthorized")
		}
		accessToken = string(bs)
		resp.Body.Close()
		ioutil.WriteFile("/data/.edgescale.cred", bs, 0400)
		return nil
	})

	url = fmt.Sprintf("%s/devices/%s/endpoints", esconf.API, deviceID)
	client = &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Accept", fmt.Sprintf("application/json; version=%s", cfg.Version))
	req.Header.Add("access-token", accessToken)
	retry(*cfg.Retry, 5*time.Second, func() error {
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println(err.Error())
			return err
		}

		bs, err := ioutil.ReadAll(resp.Body)
		if resp.Status == "401 Unauthorized" {
			fmt.Println("Get EdgeScale endpoint: ", resp.Status)
			return errors.New("401 Unauthorized")
		}
		resp.Body.Close()
		jsonconfig.Json2env("es", bs, "/data/config.env")
		jsonconfig.AddEnvConfig("es", map[string]interface{}{"OEMID": oemID}, "/data/config.env")
		jsonconfig.AddEnvConfig("es", map[string]interface{}{"DeviceID": cfg.DeviceID}, "/data/config.env")
		return nil
	})
}

func enroll() error {
	dev_cert := fmt.Sprintf("/data/certs/edgescale.pem")
	dev_key := fmt.Sprintf("/data/private_keys/edgescale.key")
	fmt.Println("starting Phase1")
	cmd := "/usr/local/edgescale/bin/bootstrap-enroll"
	err := exec.Command("bash", "-c", cmd).Run()
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("starting Phase2")
	device_id, device_model, e_token, uri := phase2()

	country := "CN"
	state := "China"
	city := "Beijing"
	organization := ""
	organizationalUnit := ""
	emailAddress := ""

	b, err := base64.RawStdEncoding.DecodeString(cfg.TrustChain)
	ioutil.WriteFile("/data/certs/rootCA.pem", b, 0400)
	serverCA, _ := ioutil.ReadFile("/data/certs/rootCA.pem")

	//E-EST certs
	fmt.Println("starting Phase3")
	nextProto := fmt.Sprintf("x-es-%s-est-ca", GetOEMID())
	est.TLSConfig = &tls.Config{
		NextProtos: []string{nextProto},
	}
	client := est.Client{
		URLPrefix:  uri,
		Username:   device_id,
		Password:   e_token,
		ServerCert: serverCA}

	caCerts, _ := client.CaCerts()

	b_cert, err := ioutil.ReadFile("/tmp/bootstrap.pem")
	b_priv, err := ioutil.ReadFile("/tmp/bootstrap.key")

	var device_fqdn string

	if device_model == "" {
		device_fqdn, err = Get_device_fqdn(device_id)
		if err != nil {
			fmt.Println("Invalid deviceID:", device_fqdn)
			return err
		}
	} else {
		device_fqdn = fmt.Sprintf("%s.%s", device_id, device_model)
	}
	cfg.DeviceID = device_fqdn

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
		return err
	}

	ioutil.WriteFile("/data/certs/estrootca.pem", caCerts, 0400)
	ioutil.WriteFile(dev_cert, cert, 0400)

	cmd = fmt.Sprintf("echo %s > /etc/hostname && hostname -F /etc/hostname", device_id)
	exec.Command("bash", "-c", cmd).Run()

	cmd = fmt.Sprintf("sync && dd if=/run/secure.bin of=%s seek=%d bs=1M", *cfg.Dev, *cfg.DevAddr)
	exec.Command("bash", "-c", cmd).Run()
	fmt.Printf("set Hostname to %s\n", device_id)

	getEdgeScaleConfig(device_id)
	return nil
}

func main() {
	var err error
	if esconf.API == "" {
		esconf.API = "https://api.edgescale.org/v1"
	}
	InitFlags()
	openssl.EnginePath = *cfg.Engine
	if sk.SK_ITS() && *cfg.SecureLevel < 2 {
		*cfg.SecureLevel = 2
		cmd := "modprobe securekeydev || reboot"
		exec.Command("bash", "-c", cmd).Run()
	}

	Mft()

	b, _ := ioutil.ReadFile("/usr/local/edgescale/conf/edgescale-version")
	cfg.Version = strings.Trim(string(b), "\n")

	cmd := fmt.Sprintf("umount /data; dd if=%s of=/run/secure.bin skip=%d bs=1M count=1", *cfg.Dev, *cfg.DevAddr)
	err = exec.Command("bash", "-c", cmd).Run()
	if err != nil {
		fmt.Println(fmt.Sprintf("failed to open '%s", *cfg.Dev), err)
		os.Exit(1)
	}

	cmd = "sync && mount -o loop /run/secure.bin /data/"
	err = exec.Command("bash", "-c", cmd).Run()
	if err != nil {
		cmd = "fsck.ext2 -yf /run/secure.bin || mkfs.ext2 /run/secure.bin && mount /run/secure.bin /data && mkdir -p /data/{certs,private_keys}"
		err = exec.Command("bash", "-c", cmd).Run()
	}

	dev_cert := fmt.Sprintf("/data/certs/edgescale.pem")

	b, err = ioutil.ReadFile(dev_cert)
	if err != nil {
		fmt.Println("No valid certificate found, starting 3 Phases Certificate Enrollment")
	} else {
		expires, CommonName, err := ParseCertificate(b)
		if err != nil {
			fmt.Println("No valid certificate found, starting 3 Phases Certificate Enrollment")
		} else if *expires > 1 && !*cfg.ReNew {
			getEdgeScaleConfig(*CommonName)
			fmt.Printf("edgescale cert expires: %v days, skip certificate Enrollment\n", *expires)
			cmd = fmt.Sprintf("echo %s > /etc/hostname && hostname -F /etc/hostname", strings.Split(*CommonName, ".")[0])
			exec.Command("bash", "-c", cmd).Run()
			os.Exit(0)
		}
	}

	retry(*cfg.Retry, 5*time.Second, func() error {
		return enroll()
	})

}
