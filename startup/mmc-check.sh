#####################################
#
#Copyright 2017-2018 NXP
#
#####################################

#!/bin/bash
# check the MMC blocks health status

check_list="mmc"

mmc::badblocks(){
        for b in $(find /dev/ -regex '/dev/mmcblk.*p.*')
        do
                echo Checking $b
                badblocks -sv $b -o /var/log/edgescale/badblocks-$(basename $b).log
        done
}

case $1 in
        mmc)
                mmc::badblocks
                ;;
        *)
                for b in $check_list
                do
                        $b::badblocks
                done
                ;;
esac

