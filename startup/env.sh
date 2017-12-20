#####################################
#
# Copyright 2017 NXP
#
#####################################

#!/bin/bash

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

