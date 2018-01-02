package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/yosssi/gmq/mqtt"
	"github.com/yosssi/gmq/mqtt/client"
	"os"
	"os/exec"
	"time"
)

var log = logrus.New()

type Config struct {
	LogLevel *int
}

type Msg struct {
	Model_id int    `json:"model_id"`
	Mid      int    `json:"mid"`
	Solution string `json:"solution"`
	Version  string `json:"version"`
	Action   string `josn:"action"`
	Url      string `josn:"url"`
}

type Status struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
}

func InitAgent() error {
	cli := client.New(&client.Options{
		ErrorHandler: func(err error) {
			log.Println(err)
		},
	})

	defer cli.Terminate()
	device_id, err := os.Hostname()
	topic := fmt.Sprintf("device/%s", device_id)

	err = cli.Connect(&client.ConnectOptions{
		Network:         "tcp",
		Address:         "int.msg.edgescale.org:1883",
		CleanSession:    true,
		ClientID:        []byte(device_id),
		CONNACKTimeout:  10,
		PINGRESPTimeout: 10,
		KeepAlive:       30,
		TLSConfig:       nil,
	})
	if err != nil {
		return err
	}
	log.Info("Connected to int.msg.edgescale.org:1883")

	err = cli.Subscribe(&client.SubscribeOptions{
		SubReqs: []*client.SubReq{
			&client.SubReq{
				TopicFilter: []byte(topic),
				QoS:         mqtt.QoS2,
				Handler: func(topicName, message []byte) {
					log.Debug(string(message))
					var m Msg
					json.Unmarshal(message, &m)
					if m.Action == "update_firmware" {
						log.Println("Update filmware: ", m.Solution, m.Version)
						cmd := fmt.Sprintf("/usr/local/bin/ota-updateSet %s %s %d", m.Solution, m.Version, m.Mid)
						exec.Command("bash", "-c", cmd).Output()
					}
				},
			},
		},
	})
	if err != nil {
		return err
	}

	for {
		status := Status{
			ID:        device_id,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		b, _ := json.Marshal(status)

		err = cli.Publish(&client.PublishOptions{
			QoS:       mqtt.QoS0,
			TopicName: []byte("edgescale/health/internal/system/status"),
			Message:   []byte(b),
		})
		if err != nil {
			return err
		}
		time.Sleep(30 * time.Second)
	}
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

	for {
		err := InitAgent()
		if err != nil {
			log.Error(err)
			time.Sleep(5 * time.Second)
		}
	}
}
