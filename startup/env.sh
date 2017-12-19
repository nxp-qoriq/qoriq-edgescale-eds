#####################################
#
# Copyright 2017 NXP
#
#####################################

#!/bin/bash

hostnametail=ls1043.00A83.mgw.nxp
hostnameid=`date |md5sum|cut -c 1-5`

#hostnameid=00056

hostname=$(hostname)
if [[ "$hostname" == "localhost" || "$hostname" == "nxp-ls1043-00035" ]]; then
	echo $hostnameid.$hostnametail > /etc/hostname 
	hostname -F /etc/hostname
	#sed -i /nxp/d /etc/hosts
	echo "127.0.0.1       $hostnameid.$hostnametail" >>/etc/hosts
	echo "new hostname $hostnameid.$hostnametail"
fi

echo "hostname $(hostname)"
testserver="www.baidu.com"

curl --connect-timeout 10  $testserver >/dev/null 2>&1
if [ $? -ne 0 ];then
	ethlist=$(ifconfig -a|grep -e fm -e eth -e enp| cut -d" " -f1)
	for eth in $ethlist;do
		ifconfig $eth down
	done
	
	for eth in $ethlist;do
		echo "Checking for ethernet port $eth" 
		ifconfig $eth up;sleep 10
	
		if ethtool $eth|grep "Link detected: yes";then 
			dhclient -r $eth; dhclient $eth|| ifconfig $eth down
		else
			ifconfig $eth down;continue
		fi
	
		curl $testserver >/dev/null 2>&1 && \
		echo "network ethernet port is $eth"; ifconfig $eth; ip r;break
	done
	
fi

echo "Setting time from $testserver"
curl $testserver >/dev/null 2>&1 && date -s "$(curl -s --head $testserver | grep ^Date: | sed 's/Date: //g')"

