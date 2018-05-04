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
	"bitbucket.org/bertimus9/systemstat"
	"strings"
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

type SysStat struct {
        Mem  systemstat.MemSample
        LastCPUSample systemstat.CPUSample
        CurCPUSample  systemstat.CPUSample
        SysCPUAvg     systemstat.CPUAverage
        sysCPUSampled  bool
}

type Status struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	CPUUsage string `json:"cpuusage"`
	MemUsage string `json:"memusage"`
	AppNumber string `json:"appnumber"`
	EsVersion string `json:"esversion"`
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
		CleanSession:    false,
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

		Apps, err := exec.Command("bash", "-c", "docker ps -q | wc -l").Output()
		if err != nil {
			return err
		}

		Ver, err := exec.Command("bash", "-c", "cat /etc/edgescale-version").Output()
		if err != nil {
			return err
		}

		CPUPct := fmt.Sprintf("%.1f%%", CPUUsedPct)
		MemPct := fmt.Sprintf("%.1f%%", MemUsedPct)
		AppNum := fmt.Sprintf("%s", Apps)
		AppNum = strings.Replace(AppNum, "\n", "", -1)
		EsVer := fmt.Sprintf("%s", Ver)
		EsVer = strings.Replace(EsVer, "\n", "", -1)
		status := Status{
			ID:        device_id,
			Timestamp: time.Now().Format(time.RFC3339),
			CPUUsage: CPUPct,
			MemUsage: MemPct,
			AppNumber: AppNum,
			EsVersion: EsVer,
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
