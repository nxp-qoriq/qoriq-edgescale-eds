/*
 **********************************
 *
 * Copyright 2018 NXP
 *
 **********************************
 */

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yosssi/gmq/mqtt"
	"github.com/yosssi/gmq/mqtt/client"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

type Logurl struct {
	URL string `json:"url"`
}

type LogMeta struct {
	ID      string `json:"id"`
	Logtype string `json:"logtype"`
	Logname string `json:"logname"`
}

func get_endpoint(logname string) (string, error) {

	// Get device ID
	device_id, err := os.Hostname()
	if err != nil {
		return "", err
	}
	host := "https://api.edgescale.org/public"
	_url := "/devices/logs/signer"

	url := fmt.Sprintf("%s%s?device_id=%s&logname=%s", host, _url, device_id, logname)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// Make the client and post log to cloud
	client := &http.Client{Transport: tr}
	res, err := client.Get(url)
	if err != nil {
		log.Println("get endpoint: ", err)
		return "", err
	}
	defer res.Body.Close()
	message, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println("Http body ReadAll:", err)
		return "", err
	}
	var s Logurl
	err = json.Unmarshal(message, &s)
	if err != nil {
		log.Println("json Unmarshal:", err)
		return "", err
	}
	if strings.HasPrefix(s.URL, "http") {
		return s.URL, nil
	}
	return "", errors.New(fmt.Sprintf("Invalid URL:%s %s", s.URL, string(message)))
}

func putfile(url string, content []byte) error {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// Make the client and post log to cloud
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(content))
	if err != nil {
		log.Println("post error:", err)
		return err
	}
	_, err = client.Do(req)
	return err
}

func Upload_syslog(logname string) error {

	endurl, err := get_endpoint(logname)
	if err != nil {
		return err
	}
	_log, err := exec.Command("bash", "-c", "dmesg").Output()
	if err != nil {
		return err
	}
	return putfile(endurl, _log)
}

func Upload_kubelog(logname string) error {

	endurl, err := get_endpoint(logname)
	if err != nil {
		return err
	}
	_log, err := exec.Command("bash", "-c", "tail -2000 /var/log/kubelet.log").Output()
	if err != nil {
		return err
	}
	return putfile(endurl, _log)
}

func Upload_mqlog(logname string) error {

	endurl, err := get_endpoint(logname)
	if err != nil {
		return err
	}
	_log, err := exec.Command("bash", "-c", "tail -2000 /var/log/edgescale/mq-agent.log").Output()
	if err != nil {
		return err
	}
	return putfile(endurl, _log)
}

func Upload_puppetlog(logname string) error {

	endurl, err := get_endpoint(logname)
	if err != nil {
		return err
	}
	_log, err := exec.Command("bash", "-c", "grep -a puppet-agent /var/log/syslog*|tail -2000").Output()
	if err != nil {
		return err
	}
	return putfile(endurl, _log)
}

func Putlog_tocloud(logtype string) (string, error) {
	var logname string
	switch logtype {
	case "sys":
		logname = "syslog.txt"
		err := Upload_syslog(logname)
		if err != nil {
			return "", err
		}
	case "mqtt":
		logname = "mqttlog.txt"
		err := Upload_mqlog(logname)
		if err != nil {
			return "", err
		}
	case "kubelet":
		logname = "kubeletlog.txt"
		err := Upload_kubelog(logname)
		if err != nil {
			return "", err
		}
	case "puppet":
		logname = "puppetlog.txt"
		err := Upload_puppetlog(logname)
		if err != nil {
			return "", err
		}
	default:
		log.Println("Unknown logtype:", logtype)
		return "", errors.New(fmt.Sprintf("Unknown logtype: %s", logtype))
	}
	log.Printf("Log is updated type/name: %s/%s", logtype, logname)
	return logname, nil
}

func Action_uploadlog(cli *client.Client, device_id string, m Msg) error {
	logname, err := Putlog_tocloud(m.Type)
	if err != nil {
		log.Println("Upload log error: ", err)
		return err
	}
	if logname == "" {
		log.Println("Logname should not be null")
		return errors.New("logname null")
	}

	logmeta := LogMeta{
		ID:      device_id,
		Logname: logname,
		Logtype: m.Type,
	}
	lmeta, _ := json.Marshal(logmeta)
	err = cli.Publish(&client.PublishOptions{
		QoS:       mqtt.QoS0,
		TopicName: []byte("edgescale/system/devices/logs/all"),
		Message:   []byte(lmeta),
	})
	return err
}
