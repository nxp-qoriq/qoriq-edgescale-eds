#####################################
#
# Copyright 2017-2018 NXP
#
#####################################

#!/bin/bash

testserver="https://www.linux.org"
ok=1
which dhclient||udhcpc=1

httpdate() {
    s=$1
    origdate=`curl -k --connect-timeout 30 -s --head $s | grep -i ^Date:|head -n 1 |cut -c 6-`

    d=`echo "$origdate" | awk '{print $2}'`
    m=`echo "$origdate" | awk '{print $3}'`
    y=`echo "$origdate" | awk '{print $4}'`

    t=`echo "$origdate" | awk '{print $5}'`
    h=`echo $t |awk -F: '{print $1$2}'`
    s=`echo $t |awk -F: '{print $3}'`

    case  "$m" in
            "Jan")
                    m="01"
                    ;;
            "Feb")
                    m="02"
                    ;;
            "Mar")
                    m="03"
                    ;;
            "Apr")
                    m="04"
                    ;;
            "May")
                    m="05"
                    ;;
            "Jun")
                    m="06"
                    ;;
            "Jul")
                    m="07"
                    ;;
            "Aug")
                    m="08"
                    ;;
            "Sep")
                    m="09"
                    ;;
            "Oct")
                    m="10"
                    ;;
            "Nov")
                    m="11"
                    ;;
            "Dec")
                    m="12"
                    ;;
            *)
                    echo "Get month $m error"
                    ;;
    esac

    newdate="$m$d$h$y.$s"
    #echo "Update date $newdate"

    if [ -z "$t" ]; then
        return 1
    fi
    if [ -z "$h" ]; then
        return 1
    fi

    date -s "$origdate" && return 0
    #echo date -u "$newdate"
    date -u "$newdate"
    return $?

}


curl -k --connect-timeout 10 $testserver >/dev/null 2>&1
if [ $? -ne 0 ];then
	ok=0
	ethlist=$(ip -o link show|awk -F ":" '{print $2}'|sed 's/\ //g'|grep -ie fm -ie ^e)
	for eth in $ethlist;do
		ifconfig $eth down
	done
	
	for eth in $ethlist;do
		echo "Checking for ethernet port $eth" 
		ifconfig $eth up;sleep 10
	
		if ethtool $eth|grep "Link detected: yes";then
			if [ -z $udhcpc ];then
				dhclient -r $eth; dhclient $eth
			else
				udhcpc -i $eth
			fi

			ip r |grep "default"
			if [ $? -ne 0 ];then
				ifconfig $eth down;continue
			fi
				
		else
			ifconfig $eth down;continue
		fi
	
		curl -k --connect-timeout 30 $testserver >/dev/null 2>&1 && \
		ok=1;echo "network ethernet port is $eth"; ifconfig $eth; ip r;break
	done
	
fi
#for a in `seq 5`; do
for a in 1 2 3 4 5;do
    for s in $testserver "https://www.baidu.com" "https://www.google.com";do
        echo "Setting time from $s"
        httpdate $s
        if [ $? -eq 0 ];then
            break 2
        fi
    done
    sleep 2
done
