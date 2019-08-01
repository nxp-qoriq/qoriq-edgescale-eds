#####################################
#
# Copyright 2017-2019 NXP
#
#####################################

#!/bin/bash
updateStatus=`cat /tmp/ota-info | awk '{print $1}'`
platform=`cat /tmp/ota-info | awk '{print $2}'`
oldimageVersion=`cat /tmp/ota-info | awk '{print $3}'`
newimageVersion=`cat /tmp/ota-info | awk '{print $4}'`
solutionname=`cat /tmp/ota-info | awk '{print $5}'`
solutionid=`cat /tmp/ota-info | awk '{print $6}'`
autoOta=`cat /tmp/ota-info | awk '{print $7}'`
oldmid=`cat /tmp/ota-info | awk '{print $8}'`
mid=$1

if [ "$mid" == "$oldmid" ];then
    exit 0
else
    echo "$updateStatus $platform $oldimageVersion $newimageVersion $solutionname $solutionid $autoOta $mid" > /tmp/ota-info
    dd if=/tmp/ota-info of=/dev/mmcblk0 bs=512 seek=129024 count=1 conv=sync
    if [ $? = 0 ];then
    	reboot -f
    else
    	exit 0
    fi
fi

