package main

import (
	"errors"
	"fmt"
	"github.com/joho/godotenv"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

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

func serviceRecover() error {
	cmd := fmt.Sprintf("pgrep edgescale")
	err := exec.Command("bash", "-c", cmd).Run()
	if err != nil {
		serviceRestart()
		return nil
	}
	err = checkNetwork()
	if err != nil {
		cmd = fmt.Sprintf("env.sh")
		exec.Command("bash", "-c", cmd).Run()
	}
	return nil
}

func checkNetwork() error {
	_, err := net.Dial("tcp", "ntp.org:443")
	return err
}

func serviceRestart() {
	cmdList := []string{
		"killall -9 cert-agent mq-agent",
		"/usr/local/edgescale/bin/env.sh",
		"/usr/local/edgescale/bin/cert-agent -retry 3",
		"start-stop-daemon --start --startas /usr/local/edgescale/bin/mq-agent --name mq-agent -m --pidfile /var/run/mq-agent.pid -b",
	}
	for _, cmd := range cmdList {
		exec.Command("bash", "-c", cmd).Run()
	}
}

func serviceCheck() error {
	var (
		err  error
		cmd  string
		mqtt []string
	)
	err = godotenv.Load("/data/config.env")
	if err != nil {
		return err
	}
	mqtt = strings.Split(os.Getenv("ES_MQTT_URI"), ":")
	if len(mqtt) != 2 {
		return errors.New("invalid mqtt uri")
	}
	ips, err := net.LookupIP(mqtt[0])
	if err != nil {
		return err
	}
	cmd = fmt.Sprintf("netstat -tWnp $(cat /var/run/mq-agent.pid) | grep %s:%s.*ESTABLISHED", ips[0].String(), mqtt[1])
	err = exec.Command("bash", "-c", cmd).Run()
	if err != nil {
		return err
	}
	return nil
}

func main() {
	for {
		err := retry(3, time.Minute, serviceCheck)
		if err != nil {
			serviceRecover()
		}
	}
}
