#!/bin/bash

/usr/local/bin/cert-agent
. /data/config.env

status=$(curl -X DELETE -H "Content-Type: application/json; version=$(cat /etc/edgescale-version)" -H "access-token: $(cat /data/.edgescale.cred)" -s $ES_API_URI/enroll/device/$HOSTNAME)
root=$(mount | grep "/ " | awk '{print $1}')

if [ $status -ge 2 ]
then
		case $root in
				/dev/mmcblk*)
						dd if=/dev/zero of=$(echo $root | cut -c 1-12) bs=10M status=progress
						;;
				/dev/sd*)
						dd if=/dev/zero of=$(echo $root | cut -c 1-8) bs=10M status=progress
						;;
		esac
fi
