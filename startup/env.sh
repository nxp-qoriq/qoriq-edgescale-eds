#####################################
#
# Copyright 2017 NXP
#
#####################################

#!/bin/bash

testserver="https://portal.edgescale.org"
ok=1

curl -k --connect-timeout 10  $testserver >/dev/null 2>&1
if [ $? -ne 0 ];then
	ok=0
	ethlist=$(ifconfig -a|grep -e fm -e eth -e enp| cut -d" " -f1)
	for eth in $ethlist;do
		ifconfig $eth down
	done
	
	for eth in $ethlist;do
		echo "Checking for ethernet port $eth" 
		ifconfig $eth up;sleep 10
	
		if ethtool $eth|grep "Link detected: yes";then 
			dhclient -r $eth; dhclient $eth;ifconfig $eth |grep  "inet addr:"
			if [ $? -ne 0 ];then
				ifconfig $eth down;continue
			fi
				
		else
			ifconfig $eth down;continue
		fi
	
		curl -k $testserver >/dev/null 2>&1 && \
		ok=1;echo "network ethernet port is $eth"; ifconfig $eth; ip r;break
	done
	
fi
if [ $ok -eq 1 ];then
	echo "Setting time from $testserver"
	curl -k $testserver >/dev/null 2>&1 && date -s "$(curl -k -s --head $testserver | grep ^Date: | sed 's/Date: //g')"
else 
	echo "Using default time"
	date -u
	exit 1
fi
