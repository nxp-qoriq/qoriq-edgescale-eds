/*
 **********************************
 *
 * Copyright 2018 NXP
 *
 **********************************
 */

package main

import (
	"../cert-agent/pkg/openssl"
	"github.com/sigma/systemstat"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
	"strconv"
	"github.com/shirou/gopsutil/disk"
)

var log = logrus.New()

type Config struct {
	LogLevel *int
}

type Msg struct {
	Model_id int    `json:"model_id"`
	Mid      string `json:"mid"`
	Solution string `json:"solution"`
	Version  string `json:"version"`
	Action   string `josn:"action"`
	Url      string `josn:"url"`
	Type     string `josn:"type"`
}

type SysStat struct {
	Mem           systemstat.MemSample
	LastCPUSample systemstat.CPUSample
	CurCPUSample  systemstat.CPUSample
	SysCPUAvg     systemstat.CPUAverage
	sysCPUSampled bool
}

type DiskStat struct {
	DskFree         string
	DskUsed         string
}

type Status struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	CPUUsage  string `json:"cpuusage"`
	MemUsage  string `json:"memusage"`
	AppNumber string `json:"appnumber"`
	EsVersion string `json:"esversion"`
	IpAddr    string `json:"ipaddress"`
	DiskFree  string `json:"diskfree"`
	DiskUsed  string `json:"diskused"`
}

var routinesync = make(chan bool, 1)

func InitAgent() error {
	device_id, err := os.Hostname()
	topic := fmt.Sprintf("device/%s", device_id)

	certPEMBlock, _ := ioutil.ReadFile("/data/certs/edgescale.pem")
	keyPEMBlock, _ := ioutil.ReadFile("/data/private_keys/edgescale.key")
	cert, err := openssl.X509KeyPair(certPEMBlock, keyPEMBlock, "/data/private_keys/edgescale.key")
	if err != nil {
		return err
	}
	nextproto := fmt.Sprintf("x-es-%s-mqtt-ca", os.Getenv("ES_OEMID"))

	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	serverCert, _ := ioutil.ReadFile("/data/certs/rootCA.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(serverCert)
	tlsConfig.RootCAs = caCertPool
	tlsConfig.NextProtos = []string{nextproto}

	opts := &mqtt.ClientOptions{
		ClientID:       device_id,
		PingTimeout:    time.Second * 30,
		ConnectTimeout: time.Second * 30,
		AutoReconnect:  true,
		KeepAlive:      60,
		TLSConfig:      &tlsConfig,
	}

	MQTTURL := fmt.Sprint("ssl://", os.Getenv("ES_MQTT_URI"))
	log.Info("Connected to: ", MQTTURL)
	opts.AddBroker(MQTTURL)
	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		log.Info("Connect error: ", token.Error())
		return token.Error()
	}

	defer client.Disconnect(3)

	if token := client.Subscribe(topic, 2, func(client mqtt.Client, msg mqtt.Message) {
		var m Msg
		json.Unmarshal(msg.Payload(), &m)
		switch m.Action {
		case "update_firmware":
			log.Println("Update filmware: ", m.Solution, m.Version)
			cmd := fmt.Sprintf("/usr/local/edgescale/bin/ota-updateSet %s %s %s", m.Solution, m.Version, m.Mid)
			exec.Command("bash", "-c", cmd).Output()
		case "unenroll":
			log.Println("Unenroll device certificate")
			cmd := fmt.Sprintf("dd if=/dev/zero of=/dev/mmcblk0 bs=1M seek=62 count=1 && reboot")
			exec.Command("bash", "-c", cmd).Output()
		case "uploadlog":
			log.Printf("upload %s log msg recvd", m.Type)
			Action_uploadlog(client, device_id, m)
		case "update_software":
			log.Println("Update software: ", m.Solution, m.Version, m.Mid)
			cmd := fmt.Sprintf("kill -s SIGUSR1 $(<'/var/run/puppetlabs/agent.pid')")
			exec.Command("bash", "-c", cmd).Output()
		case "factory_reset":
			cmd := fmt.Sprintf("/usr/local/edgescale/bin/factory_reset.sh")
			exec.Command("bash", "-c", cmd).Output()
		}
	}); token.Wait() && token.Error() != nil {
		log.Info("Subscribe error: ", token.Error())
		return token.Error()
	}

	if token := client.Subscribe(fmt.Sprintf("edgescale/kube/devices/%s", device_id), 2, MqAppHandler); token.Wait() && token.Error() != nil {
		log.Info("Subscribe error: ", token.Error())
		return token.Error()
	}

	go func() {
		<-routinesync
		log.Infoln("Starting app agent")
		_ = Listen_and_loop(client, device_id)
		log.Warnln("app agent stoped")
		routinesync <- true
	}()

	sysstat := SysStat{}
	for {
		var CPUUsedPct, MemUsedPct float64
		sysstat.LastCPUSample = sysstat.CurCPUSample
		sysstat.CurCPUSample = systemstat.GetCPUSample()
		if !sysstat.sysCPUSampled {
			sysstat.sysCPUSampled = true
			continue
		}
		sysstat.SysCPUAvg = systemstat.GetCPUAverage(sysstat.LastCPUSample, sysstat.CurCPUSample)
		CPUUsedPct = 100 - sysstat.SysCPUAvg.IdlePct

		sysstat.Mem = systemstat.GetMemSample()
		MemUsed := sysstat.Mem.MemTotal - sysstat.Mem.MemFree - sysstat.Mem.Cached - sysstat.Mem.Buffers
		MemUsedPct = 100 * float64(MemUsed) / float64(sysstat.Mem.MemTotal)

		Apps, err := exec.Command("bash", "-c", fmt.Sprintf("ls %s|wc -l", MANIFEST)).Output()
		if err != nil {
			return err
		}

		Ver, err := exec.Command("bash", "-c", "cat /usr/local/edgescale/conf/edgescale-version").Output()
		if err != nil {
			return errors.New("Error: read edgescale-version")
		}

		CPUPct := fmt.Sprintf("%.1f%%", CPUUsedPct)
		MemPct := fmt.Sprintf("%.1f%%", MemUsedPct)
		AppNum := fmt.Sprintf("%s", Apps)
		AppNum = strings.Replace(AppNum, "\n", "", -1)
		EsVer := fmt.Sprintf("%s", Ver)
		EsVer = strings.Replace(EsVer, "\n", "", -1)
		DskStat := GetDiskUsageStat()
		status := Status{
			ID:        device_id,
			Timestamp: time.Now().Format(time.RFC3339),
			CPUUsage:  CPUPct,
			MemUsage:  MemPct,
			AppNumber: AppNum,
			EsVersion: EsVer,
			IpAddr:    GetLocalIp(),
			DiskFree:  DskStat.DskFree,
			DiskUsed:  DskStat.DskUsed,
		}
		b, _ := json.Marshal(status)
		if token := client.Publish("edgescale/health/internal/system/status", 0, false, b); token.Wait() && token.Error() != nil {
			log.Info("Publish error", token.Error())
		}
		time.Sleep(30 * time.Second)
	}
}

func GetLocalIp() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func GetDiskUsageStat() DiskStat {
	u, err := disk.Usage("/")
	if err != nil {
		panic(err)
	}
	du := DiskStat{}
	du.DskFree  = strconv.FormatUint(u.Free /1024/1024/1024, 10) + " GB"
	du.DskUsed  = strconv.FormatUint(u.Used /1024/1024/1024, 10) + " GB"
	return du
}

func InitFlags() Config {
	cfg := Config{}
	cfg.LogLevel = flag.Int("d", 4, "logging levels 0-5")
	flag.Parse()
	return cfg
}

func main() {
	cfg := InitFlags()

	log.SetLevel(logrus.Level(*cfg.LogLevel))
	log.Out = os.Stdout
	_, err := os.Stat("/var/log/edgescale")
	if err != nil {
		err = os.MkdirAll("/var/log/edgescale/", 0644)
		if err != nil {
			log.Error(err)
		}
	}
	fd, err := os.OpenFile("/var/log/edgescale/mq-agent.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = fd
	} else {
		log.Info("Failed to log to file, using default stderr")
	}
	defer fd.Close()
	routinesync <- true
	for {
		err := InitAgent()
		if err != nil {
			log.Error("MQ-agent: ", err)
			time.Sleep(5 * time.Second)
		}
	}
}
