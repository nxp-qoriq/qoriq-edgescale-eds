/*
 **********************************
 *
 * Copyright 2019 NXP
 *
 **********************************
 */

package main

import (
	"encoding/json"
	"fmt"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/sirupsen/logrus"
	"os"
	"time"
)

const glog_path string = "/var/log/edgescale/"
const glog_name string = "mq-gateway.log"

var gateway_client mqtt.Client
var agent_client mqtt.Client
var logger = logrus.New()
var loop_flag bool = true

var ADDRESS string = "127.0.0.1:1883"
var ACCESS_KEY string = ""
var DEVICE_ID string = ""
var CLIENTID string = "Mq_Gateway_Forward_id0"

var BASE_TOPIC string = "/edgescale"
var REG_TOPIC string = ""
var REG_RET_TOPIC string = ""
var SET_TOPIC string = ""
var SET_RET_TOPIC string = ""
var GET_TOPIC string = ""
var GET_RET_TOPIC string = ""
var OTA_TOPIC string = ""
var OTA_RET_TOPIC string = ""

type MqMsgHeader struct {
	Topic   string `json:"topic"`
	Version string `json:"version"`
	Msgid   string `json:"msgid"`
	Time    string `json:"utctime"`
}

func InitLogFile() (retfd *os.File, reterr error) {
	logger.SetLevel(logrus.Level(6))
	logger.Out = os.Stdout

	_, err := os.Stat(glog_path)
	if err != nil {
		err = os.MkdirAll(glog_path, 0755)
		if err != nil {
			logger.Error(err)
		}
	}

	fd, err := os.OpenFile(glog_path+glog_name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		logger.Out = fd
	} else {
		logger.Info("Failed to log to file, using default stderr")
	}

	return fd, nil
}

func MqInitVariable() error {
	ACCESS_KEY = "access_key0"
	DEVICE_ID = "i.MX-RT_id0"

	REG_TOPIC = BASE_TOPIC + "/" + ACCESS_KEY + "/" + DEVICE_ID + "/thing/register"
	REG_RET_TOPIC = BASE_TOPIC + "/" + ACCESS_KEY + "/" + DEVICE_ID + "/thing/register/result"

	SET_TOPIC = BASE_TOPIC + "/" + ACCESS_KEY + "/" + DEVICE_ID + "/thing/set"
	SET_RET_TOPIC = BASE_TOPIC + "/" + ACCESS_KEY + "/" + DEVICE_ID + "/thing/set/result"

	GET_TOPIC = BASE_TOPIC + "/" + ACCESS_KEY + "/" + DEVICE_ID + "/thing/get"
	GET_RET_TOPIC = BASE_TOPIC + "/" + ACCESS_KEY + "/" + DEVICE_ID + "/thing/get/result"

	OTA_TOPIC = BASE_TOPIC + "/" + ACCESS_KEY + "/" + DEVICE_ID + "/thing/ota"
	OTA_RET_TOPIC = BASE_TOPIC + "/" + ACCESS_KEY + "/" + DEVICE_ID + "/thing/ota/result"

	return nil
}

func InitMqttClient(device_id string) (mqcli mqtt.Client, err error) {
	opts := &mqtt.ClientOptions{
		ClientID:       device_id,
		PingTimeout:    time.Second * 30,
		ConnectTimeout: time.Second * 30,
		AutoReconnect:  true,
		KeepAlive:      60,
		//		TLSConfig:      &tlsConfig,
	}

	MQTTURL := fmt.Sprint("tcp://", ADDRESS)
	logger.Info("Connected to: ", MQTTURL)
	opts.AddBroker(MQTTURL).SetConnectionLostHandler(MqConnLostHandler)

	client := mqtt.NewClient(opts)

	token := client.Connect()
	if token.Wait(); token.Error() != nil {
		logger.Info("Connect error: ", token.Error())
		return client, token.Error()
	}

	var topic_array = []string{REG_TOPIC, SET_RET_TOPIC, GET_RET_TOPIC, OTA_RET_TOPIC}
	for idx, topic := range topic_array {
		fmt.Printf("gateway subscribe topic%d:%s\n", idx, topic)
		token := client.Subscribe(topic, 1, MqRecvGwCallback)
		if token.Wait(); token.Error() != nil {
			logger.Info("Subscribe error: ", token.Error())
			return client, token.Error()
		}
	}

	return client, nil
}

/*
	when received message(whose topic is "register", "set_result",
	"get_result" and "ota_result") from gateway(sub-devices) via local-broker,
	we will forward it to edgescale cloud via agent.

	Note: mqcli is client handler for local-broker
*/
func MqRecvGwCallback(mqcli mqtt.Client, msg mqtt.Message) {
	var topic = ""
	var mqj MqMsgHeader

	logger.Debugf("MqRecvGwCallback topic recvd: %s", msg.Topic())
	fmt.Printf("topic:%s message recvd: %s\n", msg.Topic(), string(msg.Payload()))

	opts := mqcli.OptionsReader()
	device_id := opts.ClientID()
	fmt.Printf("devid:%s\n", device_id)

	err := json.Unmarshal(msg.Payload(), &mqj)
	if err != nil {
		fmt.Printf("recvd topic:%s err:%s\n", mqj.Topic, err)
		return
	}

	fmt.Printf("MqRecvGwCallback topic:%s ver:%s msgid:%s time:%s\n", mqj.Topic, mqj.Version, mqj.Msgid, mqj.Time)

	switch mqj.Topic {
	case "register":
		fmt.Printf("received register\n")
		topic = REG_TOPIC

	case "set_result":
		fmt.Printf("received set_result\n")
		topic = SET_RET_TOPIC

	case "get_result":
		fmt.Printf("received get_result\n")
		topic = GET_RET_TOPIC

	case "ota_result":
		fmt.Printf("received ota_result\n")
		topic = OTA_RET_TOPIC

	default:
		fmt.Printf("received unknown topic:\"%s\"\n", mqj.Topic)
	}

	if topic != "" {
		MqForwardToCloud(topic, msg.Payload())
	}
}

func MqConnLostHandler(c mqtt.Client, err error) {
	fmt.Printf("MQTT Connection lost, reason: %v\n", err)
	c.Disconnect(1000)
}

func MqForwardToCloud(topic string, msg []byte) error {
	cli := agent_client
	token := cli.Publish(topic, 0, false, msg)
	if token.Wait(); token.Error() != nil {
		return token.Error()
	}

	return nil
}

func MqForwardToGateway(topic string, msg []byte) error {
	cli := gateway_client
	token := cli.Publish(topic, 0, false, msg)
	if token.Wait(); token.Error() != nil {
		return token.Error()
	}

	return nil
}

/*
	when received message(whose topic is "register_result", "set",
	"get" and "ota") from edgescale cloud via agent, we will forward it to
	gateway(sub-devices) via local-broker

	Note: mqcli is client handler for communication between agent and cloud
*/
func MqRecvCloudCallback(mqcli mqtt.Client, msg mqtt.Message) {
	var topic = ""
	var mqj MqMsgHeader

	logger.Debugf("MqRecvCloudCallback topic recvd: %s", msg.Topic())
	fmt.Printf("topic:%s message recvd: %s\n", msg.Topic(), string(msg.Payload()))

	opts := mqcli.OptionsReader()
	device_id := opts.ClientID()
	fmt.Printf("devid:%s\n", device_id)

	err := json.Unmarshal(msg.Payload(), &mqj)
	if err != nil {
		fmt.Printf("recvd topic:%s err:%s\n", mqj.Topic, err)
		return
	}

	fmt.Printf("MqRecvCloudCallback topic:%s ver:%s msgid:%s time:%s\n", mqj.Topic, mqj.Version, mqj.Msgid, mqj.Time)

	switch mqj.Topic {
	case "register_result":
		fmt.Printf("received register\n")
		topic = REG_RET_TOPIC

	case "set":
		fmt.Printf("received set_result\n")
		topic = SET_TOPIC

	case "get":
		fmt.Printf("received get_result\n")
		topic = GET_TOPIC

	case "ota":
		fmt.Printf("received ota_result\n")
		topic = OTA_TOPIC

	default:
		fmt.Printf("received unknown topic:\"%s\"\n", mqj.Topic)
	}

	if topic != "" {
		MqForwardToGateway(topic, msg.Payload())
	}
}

func MqGatewayMain(cli mqtt.Client) {
	agent_client = cli

	fd, err := InitLogFile()
	if err != nil {
		fmt.Println("InitLogFile err:%s", err)
	}

	MqInitVariable()

	mqclient, err := InitMqttClient(CLIENTID)
	gateway_client = mqclient

	defer fd.Close()
	defer mqclient.Disconnect(3)

	sec := 0
	for loop_flag {
		sec++
		//fmt.Printf("sec:%d\n", sec)
		time.Sleep(1 * time.Second)
	}

	return
}
