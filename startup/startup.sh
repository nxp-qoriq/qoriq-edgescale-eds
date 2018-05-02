#####################################
#
# Copyright 2017 NXP
#
#####################################

#!/bin/bash


push_publicip() {
	# Get public IP
	publicip=`curl -k https://checkip.amazonaws.com`

	token=""
	url="https://api.edgescale.org/public/devices/positions"
	# Create curl body
	body="{"ip": "$publicip", "device_name": "`hostname`"}"

	curl -X POST -H "Content-Type: application/json" -H "dcca_token: $token" $url -d "$body"
}

cd /usr/local/bin/

./env.sh
./cert-agent

if [ $? -eq 0 ];then
    # report public IP Address to cloud
    push_publicip

    # start puppet agent
    ./puppet.sh --certname $(cat /etc/hostname | tr -d '\n') --server int.proxy.edgescale.org \
	    --localcacert /etc/ssl/private/edgescale/certs/estrootca.pem

    # starting kubelet
    ./k8s.sh

    # check OTA status
    ./ota-statuscheck &

    # starting mq-agent
    start-stop-daemon --start --startas /usr/local/bin/mq-agent --name mq-agent -m --pidfile /var/run/mq-agent.pid -b
fi
