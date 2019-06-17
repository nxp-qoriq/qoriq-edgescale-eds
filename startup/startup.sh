#####################################
#
# Copyright 2017-2018 NXP
#
#####################################

#!/bin/bash

export version=`cat /usr/local/edgescale/conf/edgescale-version`

push_publicip() {
	# Get public IP
	publicip=`curl -k https://checkip.amazonaws.com`

	token=$(cat /data/.edgescale.cred)
	url="$ES_API_URI/devices/positions"
	# Create curl body
	body="{"ip": "$publicip", "device_name": "$ES_DEVICEID"}"

	curl -X POST -H "Content-Type: application/json; verson=$version" -H "access-token: $token" $url -d "$body"
}

cd /usr/local/edgescale/bin/
mkdir -p /data

backuppartition=/Imagebackup
mkdir -p $backuppartition
mount -o loop /dev/mmcblk0p3 $backuppartition

./env.sh
start-stop-daemon --start --startas /usr/local/edgescale/bin/es-watchdog --name es-watchdog -m --pidfile /var/run/es-watchdog.pid -b
start-stop-daemon --start --startas /bin/tee-supplicant --name tee-supplicant -m --pidfile /var/run/tee-supplicant.pid -b
./cert-agent

. /data/config.env
for env in $(set | grep ^ES)
do
	export ${env}
done

if [ -z $ES_OEM_TRUST_CA ] ; then
		rm -rf /usr/local/share/ca-certificates/es-oem-trust.crt
		update-ca-certificates
else
		echo -n $ES_OEM_TRUST_CA | base64 -d > /usr/local/share/ca-certificates/es-oem-trust.crt
		update-ca-certificates
fi

if [ $? -eq 0 ];then
    # report public IP Address to cloud
    push_publicip

    # starting kubelet
    ./k8s.sh

    # check OTA status
    ./ota-statuscheck &

    # check MMC blocks health status
    ./mmc-check.sh &

    # starting mq-agent
    start-stop-daemon --start --startas /usr/local/edgescale/bin/mq-agent --name mq-agent -m --pidfile /var/run/mq-agent.pid -b
fi
