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
var agent_log *logrus.Logger = nil

var ADDRESS string = "127.0.0.1:1883"
var ACCESS_KEY string = ""
var DEVICE_ID string = ""

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

func InitLogFile() (*os.File, error) {
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

func MqLogInfo(info string, logFlag bool) error {
	fmt.Printf("\n%s\n", info)

	if logFlag {
		logger.Info(info)

		if agent_log != nil {
			agent_log.Info(info)
		}
	}

	return nil
}

func MqInitVariable() error {
	ACCESS_KEY = os.Getenv("ES_ACCESSKEY")
	DEVICE_ID = os.Getenv("ES_DEVICEID")

	fmt.Printf("access_key:%s device_id:%s\n", ACCESS_KEY, DEVICE_ID)

	basetopic := BASE_TOPIC + "/" + ACCESS_KEY + "/" + DEVICE_ID

	REG_TOPIC = basetopic + "/thing/register"
	REG_RET_TOPIC = basetopic + "/thing/register/result"

	SET_TOPIC = basetopic + "/thing/set"
	SET_RET_TOPIC = basetopic + "/thing/set/result"

	GET_TOPIC = basetopic + "/thing/get"
	GET_RET_TOPIC = basetopic + "/thing/get/result"

	OTA_TOPIC = basetopic + "/thing/ota"
	OTA_RET_TOPIC = basetopic + "/thing/ota/result"

	return nil
}

func InitMqttClient(device_id string) (mqtt.Client, error) {
	opts := &mqtt.ClientOptions{
		ClientID:       device_id,
		PingTimeout:    time.Second * 30,
		ConnectTimeout: time.Second * 30,
		AutoReconnect:  true,
		KeepAlive:      60,
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
		logInfo := fmt.Sprintf("gateway subscribe topic%d:%s", idx, topic)
		MqLogInfo(logInfo, true)
		token := client.Subscribe(topic, 2, MqRecvGwCallback)
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

	opts := mqcli.OptionsReader()
	device_id := opts.ClientID()

	logInfo := fmt.Sprintf("**MqRecvGwCallback topic:%s devid:%s message:", msg.Topic(), device_id)
	MqLogInfo(logInfo, true)

	logInfo = fmt.Sprintf("%s", string(msg.Payload()))
	MqLogInfo(logInfo, false)

	err := json.Unmarshal(msg.Payload(), &mqj)
	if err != nil {
		logInfo := fmt.Sprintf("**recvd topic:%s err:%s", mqj.Topic, err)
		MqLogInfo(logInfo, true)
		return
	}

	logInfo = fmt.Sprintf("**topic:%s ver:%s msgid:%s time:%s", mqj.Topic, mqj.Version, mqj.Msgid, mqj.Time)
	MqLogInfo(logInfo, true)

	switch mqj.Topic {
	case "register":
		topic = REG_TOPIC

	case "set_result":
		topic = SET_RET_TOPIC

	case "get_result":
		topic = GET_RET_TOPIC

	case "ota_result":
		topic = OTA_RET_TOPIC

	default:
		logInfo = fmt.Sprintf("**received unknown topic:%s", mqj.Topic)
		MqLogInfo(logInfo, true)
	}

	if topic != "" {
		MqForwardToCloud(topic, msg.Payload())

		logInfo = fmt.Sprintf("**MqRecvGwCallback -> MqForwardToCloud topic:%s", topic)
		MqLogInfo(logInfo, true)
	}
}

func MqConnLostHandler(c mqtt.Client, err error) {
	fmt.Printf("MQTT Connection lost, reason: %v\n", err)
	c.Disconnect(10)
}

func MqForwardToCloud(topic string, msg []byte) error {
	cli := agent_client
	if cli == nil {
		fmt.Printf("mqtt agent_client is nil\n")
		return nil
	}

	if !cli.IsConnectionOpen() {
		fmt.Printf("mqtt agent_client lost connection\n")
		return nil
	}

	token := cli.Publish(topic, 0, false, msg)
	if token.Wait(); token.Error() != nil {
		return token.Error()
	}

	return nil
}

func MqForwardToGateway(topic string, msg []byte) error {
	cli := gateway_client

	if !cli.IsConnectionOpen() {
		fmt.Printf("mqtt gateway_client lost connection\n")
		return nil
	}

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

	opts := mqcli.OptionsReader()
	device_id := opts.ClientID()

	logInfo := fmt.Sprintf("--MqRecvCloudCallback topic:%s devid:%s message:", msg.Topic(), device_id)
	MqLogInfo(logInfo, true)

	logInfo = fmt.Sprintf("%s", string(msg.Payload()))
	MqLogInfo(logInfo, false)

	err := json.Unmarshal(msg.Payload(), &mqj)
	if err != nil {
		logInfo = fmt.Sprintf("--recvd topic:%s err:%s", mqj.Topic, err)
		MqLogInfo(logInfo, true)
		return
	}

	logInfo = fmt.Sprintf("--topic:%s ver:%s msgid:%s time:%s", mqj.Topic, mqj.Version, mqj.Msgid, mqj.Time)
	MqLogInfo(logInfo, true)

	switch mqj.Topic {
	case "register_result":
		topic = REG_RET_TOPIC

	case "set":
		topic = SET_TOPIC

	case "get":
		topic = GET_TOPIC

	case "ota":
		topic = OTA_TOPIC

	default:
		logInfo = fmt.Sprintf("--received unknown topic:%s", mqj.Topic)
		MqLogInfo(logInfo, true)
	}

	if topic != "" {
		MqForwardToGateway(topic, msg.Payload())

		logInfo = fmt.Sprintf("--MqRecvCloudCallback -> MqForwardToGateway topic:%s", topic)
		MqLogInfo(logInfo, true)
	}
}

func MqGatewayMain(cli mqtt.Client, log *logrus.Logger) {
	agent_client = cli
	agent_log = log

	fd, err := InitLogFile()
	if err != nil {
		fmt.Println("InitLogFile err:%s", err)
	}

	mqclient, err := InitMqttClient(DEVICE_ID)
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
