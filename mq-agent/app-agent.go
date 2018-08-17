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
	"github.com/yosssi/gmq/mqtt/client"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	ACTCREATE = "create"
	ACTDELETE = "delete"
	ACTSYNC   = "sync"
	ACTSTATUS = "status"

	PENDING  = "pending"
	CREATING = "creating"
	RUNNING  = "running"
	DELETING = "deleting"
	DELETED  = "deleted"

	LOOP_INTERVAL = time.Second * 3
	MANIFEST      = "/dev/kubelet/"
	KUBELOG       = "/var/log/edgescale/kubelet.log"
)

// Kubelet container type
type Container struct {
	Image string `json:"image"`
	Name  string `json:"name"`
}

// Kubelet metadata/annotations type
type Annotation struct {
	Configseen time.Time `json:"kubernetes.io/config.seen"`
	Confighash string    `json:"kubernetes.io/config.hash"`
}

// Kubelet Pod type
type Pod struct {
	Metadata struct {
		Annotations       Annotation `json:"annotations"`
		CreationTimestamp time.Time  `json:"creationTimestamp""`
		Name              string     `json:"name"`
		Namespace         string     `json:"namespace"`
		UID               string     `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		Nodename    string      `json:"nodename"`
		Containers  []Container `json:"containers"`
		Hostnetwork bool        `json:"hostNetwork"`
	} `json:"spec"`
	Status struct {
		Phase   string `json:"phase"`
		HostIP  string `json:"hostIP"`
		Message string `json:"message"`
	} `json:"status"`
}

// Kubelet Podlist type
type Podlist struct {
	Items []Pod `json:"items"`
}

type Mqkubecmd struct {
	// type add/delete/ a pod, sync pods list
	// for upload Type is status
	//"create, delete, sync, status"
	Type       string `json:"type"`
	DeviceId   string `json:"deviceid"`
	Podname    string `json:"podname"`
	Podstatus  string `json:"podstatus"`
	Podmessage string `json:"podmessage"`
	Body       string `json:"body"`
}

type MqcmdL struct {
	// type add/delete/ a pod, sync pods list
	// for upload Type is status
	//"create, delete, sync, status"
	Type  string      `json:"type"`
	Items []Mqkubecmd `json:"items"`
}

func SendHttpRequest(argUrl string, argReq []byte, argType string) ([]byte, error) {
	req, err := http.NewRequest(argType, argUrl, bytes.NewBuffer(argReq))
	if err != nil {
		return nil, err
	}
	req.Header.Add("User-Agent", "kubectl/v1.7.0")
	req.Header.Add("Accept", "application/json")
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		ResponseHeaderTimeout: time.Second * 15,
		DisableKeepAlives:     true,
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return body, nil
}

func in_array(val string, array []string) (exists bool, index int) {
	exists = false
	index = -1

	for i, v := range array {
		if val == v {
			index = i
			exists = true
			return
		}
	}
	return
}

func in_files(val os.FileInfo, array []os.FileInfo) (exists bool, index int) {
	exists = false
	index = -1

	for i, v := range array {
		if val.Name() == v.Name() {
			index = i
			exists = true
			return
		}
	}
	return
}

func get_runningpodname() ([]string, []string, error) {

	runningpods := Podlist{}
	runnames := make([]string, 0)
	createnames := make([]string, 0)

	url := "https://127.0.0.1:10250/runningpods/"

	resp, err := SendHttpRequest(url, nil, http.MethodGet)
	if err != nil {
		log.Error("runningpods: ", err)
		return nil, nil, err
	}

	err = json.Unmarshal(resp, &runningpods)
	if err != nil {
		log.Error("runningpods: ", err)
		return nil, nil, err
	}

	for _, p := range runningpods.Items {
		if p.Spec.Containers == nil {
			createnames = append(createnames, p.Metadata.Name)
		} else {
			runnames = append(runnames, p.Metadata.Name)
		}
	}
	return runnames, createnames, err

}

func getcontainermesg(puid string) (string, error) {

	cmd := fmt.Sprintf("grep %s %s|tail -1", puid, KUBELOG)
	b, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return "exec error", err
	}

	s := string(b)
	if len(s) < 10 {
		return "null", errors.New(fmt.Sprintf("Invalid log:%s", s))
	}

	sl := strings.Split(s, "]")
	if len(sl) >= 2 {
		if strings.Contains(sl[1], "Error") {
			return sl[1], nil
		}
		return "", nil
	}
	return "null", errors.New(fmt.Sprintf("Invalid log:%s", s))
}

func get_pods() (Podlist, error) {
	_pods := Podlist{}
	url := "https://127.0.0.1:10250/pods/"

	//get all pod list
	resp, err := SendHttpRequest(url, nil, http.MethodGet)
	if err != nil {
		log.Error("Get pods: ", err)
		return _pods, err
	}
	err = json.Unmarshal(resp, &_pods)
	if err != nil {
		log.Error("Get pods: ", err)
		return _pods, err
	}

	//get running pod list
	runnings, creatings, err := get_runningpodname()
	if err != nil {
		log.Error("Get pods: ", err)
		return _pods, err
	}
	for i, p := range _pods.Items {
		ret, _ := in_array(p.Metadata.Name, runnings)
		//update for running pod list
		if ret == true {
			log.Debugf("update %s to running", _pods.Items[i].Metadata.Name)
			_pods.Items[i].Status.Phase = RUNNING
		}
		//update for creating/error pod list
		ret, _ = in_array(p.Metadata.Name, creatings)
		if ret == true {
			log.Debugf("update %s to creating", _pods.Items[i].Metadata.Name)
			_pods.Items[i].Status.Phase = CREATING
			_pods.Items[i].Status.Message, err = getcontainermesg(_pods.Items[i].Metadata.UID)
			if err != nil {
				log.Error("get log message", err)
			}
		}
		//update podname to remove nodename
		_pods.Items[i].Metadata.Name = strings.TrimSuffix(_pods.Items[i].Metadata.Name, "-"+_pods.Items[i].Spec.Nodename)
	}
	return _pods, nil

}

func getpodlisthash(pl Podlist) ([]string, []string, error) {
	n := make([]string, 0)
	h := make([]string, 0)
	for _, p := range pl.Items {
		n = append(n, p.Metadata.Name)
		h = append(h, p.Metadata.Name+p.Metadata.UID+p.Status.Phase+p.Status.Message)
	}
	//return name, hash, err
	return n, h, nil
}
func process_mqkubecmd(mqcli *client.Client, device_id string, cmdl MqcmdL) error {
	var err error = nil
	if strings.ToLower(cmdl.Type) == ACTSYNC {
		log.Info("pod syncing")
		podnames := make([]string, 0)
		for _, m := range cmdl.Items {
			if len(m.Podname) > 1 {
				podcfg := fmt.Sprintf("%s%s", MANIFEST, m.Podname)
				podnames = append(podnames, m.Podname)
				if m.Type != ACTDELETE {
					log.Infof("syncing %s", m.Podname)
					err = ioutil.WriteFile(podcfg, []byte(m.Body), 0644)
					if err != nil {
						log.Error("kube-agent: ", err)
					}
				} else {
					err := os.Remove(podcfg)
					if err != nil {
						if os.IsNotExist(err) {
							log.Warnln("pod have removed: ", m.Podname)
							deletedmessage := Mqkubecmd{
								Type:      ACTDELETE,
								DeviceId:  m.DeviceId,
								Podname:   m.Podname,
								Podstatus: DELETED,
							}
							_ = publish_mesg(mqcli, device_id, deletedmessage)
						}
					}
				}
			}
		}
		//sync and delete unexpected pods
		files, err := ioutil.ReadDir(MANIFEST)
		if err != nil {
			log.Error("kube-agent: ", err)
		}
		for _, f := range files {
			podcfg := fmt.Sprintf("%s%s", MANIFEST, f.Name())
			ret, _ := in_array(f.Name(), podnames)
			if ret == false {
				log.Warnf("kube-agent: correct unexpect pod %s", f.Name())
				err = os.Remove(podcfg)
				if err != nil {
					log.Error("kube-agent: ", err)
				}
			}
		}
		return err
	} else {
		for _, m := range cmdl.Items {
			podcfg := fmt.Sprintf("%s%s", MANIFEST, m.Podname)

			//create a new pod
			if strings.ToLower(m.Type) == ACTCREATE {
				log.Infof("Creating %s", m.Podname)
				err = ioutil.WriteFile(podcfg, []byte(m.Body), 0644)
				if err != nil {
					log.Error("kube-agent: ", err)
				}
			} else {
				//delete  pod
				log.Infof("Deleting %s", m.Podname)
				err := os.Remove(podcfg)
				if err != nil {
					if os.IsNotExist(err) {
						log.Warnln("pod have removed: ", m.Podname)
						deletedmessage := Mqkubecmd{
							Type:      ACTDELETE,
							DeviceId:  m.DeviceId,
							Podname:   m.Podname,
							Podstatus: DELETED,
						}
						_ = publish_mesg(mqcli, m.DeviceId, deletedmessage)

					}
				}
			}
		}
		return err
	}
}

func MqAppHandler(mqcli *client.Client, device_id string, topicName, message []byte) {
	var cmdl MqcmdL
	log.Debugf("topic recvd: %s", string(topicName))
	log.Debugf("message recvd: %s", string(message))

	err := json.Unmarshal(message, &cmdl)
	if err == nil {
		process_mqkubecmd(mqcli, device_id, cmdl)
	} else {
		log.Error("kube_mq_handler", err)
	}
}

func Listen_and_loop(mqcli *client.Client, device_id string) error {

	var (
		hash        = make([]string, 0)
		pnames      = make([]string, 0)
		stoped bool = false
	)

	go func() {
		for {
			if stoped == true {
				return
			}
			//Enter the gorouting Loop
			time.Sleep(5 * time.Second)
			err := MqSendSyncCmd(mqcli, device_id)
			if err != nil {
				log.Error("MqSendSyncCmd restarting is required ", err)
				stoped = true
				return
			}
			time.Sleep(5 * time.Minute)
		}
	}()

	cmd := fmt.Sprintf("mkdir -p %s", MANIFEST)
	_ = exec.Command("bash", "-c", cmd).Run()

	//Enter the Loop
	for {
		if stoped == true {
			return nil
		}
		time.Sleep(LOOP_INTERVAL)

		podlist, err := get_pods()
		if err != nil {
			log.Error("Loop get_podlist: ", err)
			continue
		}
		//report for latest pod status
		_pnames, _hash, _ := getpodlisthash(podlist)
		for i, h := range _hash {
			ret, _ := in_array(h, hash)
			if ret == true {
				log.Debug("not any changes")
				continue
			} else {

				log.Debug("changed")
				scmd, err := to_mqstatuscmd(podlist.Items[i], device_id)
				if err != nil {
					log.Error("Loop to_mqstatuscmd:", err)
					continue
				}
				err = publish_mesg(mqcli, device_id, scmd)
				if err != nil {
					log.Error("publish mq message:", err)
				}
			}
		}
		//report for deleted pod
		for _, n := range pnames {
			ret, _ := in_array(n, _pnames)
			if ret == false {
				deletedmessage := Mqkubecmd{
					Type:      ACTDELETE,
					DeviceId:  device_id,
					Podname:   n,
					Podstatus: DELETED,
				}
				err = publish_mesg(mqcli, device_id, deletedmessage)
				if err != nil {
					log.Error("publish deleted pod message:", err)
				}
			}
		}

		hash = _hash
		pnames = _pnames

	}
	return nil
}

func to_mqstatuscmd(p Pod, device_id string) (Mqkubecmd, error) {
	m, err := json.Marshal(p)

	return Mqkubecmd{
		Type:       ACTSTATUS,
		DeviceId:   device_id,
		Podname:    p.Metadata.Name,
		Podstatus:  p.Status.Phase,
		Podmessage: p.Status.Message,
		Body:       string(m),
	}, err

}

func publish_mesg(cli *client.Client, device_id string, mqcmd Mqkubecmd) error {
	topic := fmt.Sprintf("edgescale/kube/devices/app")
	m, _ := json.Marshal(mqcmd)

	log.Debugln("===========publish to mq server")

	if len(mqcmd.Type) < 2 {
		return errors.New("mqcmd invalid type")
	}
	if len(mqcmd.DeviceId) < 2 {
		return errors.New("mqcmd invalid deviceid")
	}
	log.Debugf("publish topic: %s", topic)
	log.Debugf("publish message: %s", string(m))

	err := cli.Publish(&client.PublishOptions{
		QoS:       2,
		TopicName: []byte(topic),
		Message:   []byte(m),
	})
	return err
}

func MqSendSyncCmd(mqcli *client.Client, device_id string) error {
	sycmd := Mqkubecmd{
		Type:     ACTSYNC,
		DeviceId: device_id,
	}
	err := publish_mesg(mqcli, device_id, sycmd)
	if err != nil {
		log.Error("publish sync request:", err)
		return err
	}
	log.Debugln("Sent sync request")
	return nil
}