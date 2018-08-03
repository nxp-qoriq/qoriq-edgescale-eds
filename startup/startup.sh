#####################################
#
# Copyright 2017-2018 NXP
#
#####################################

#!/bin/bash

export version=`cat /etc/edgescale-version`

push_publicip() {
	# Get public IP
	publicip=`curl -k https://checkip.amazonaws.com`

	token=""
	url="https://api.edgescale.org/v1/devices/positions"
	# Create curl body
	body="{"ip": "$publicip", "device_name": "`hostname`"}"

	curl -X POST -H "Content-Type: application/json; verson=$version" -H "dcca_token: $token" $url -d "$body"
}

cd /usr/local/bin/

./env.sh
start-stop-daemon --start --startas /bin/tee-supplicant --name tee-supplicant -m --pidfile /var/run/tee-supplicant.pid -b
./cert-agent

if [ $? -eq 0 ];then
    # report public IP Address to cloud
    push_publicip

    # starting kubelet
    ./k8s.sh

    # check OTA status
    ./ota-statuscheck &

    # starting mq-agent
    start-stop-daemon --start --startas /usr/local/bin/mq-agent --name mq-agent -m --pidfile /var/run/mq-agent.pid -b
fi
