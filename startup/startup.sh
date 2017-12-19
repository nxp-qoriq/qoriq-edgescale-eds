#####################################
#
# Copyright 2017 NXP
#
#####################################

#!/bin/bash

cd /usr/local/bin/
./env.sh
./cert-agent
./puppet.sh --certname $(cat /etc/hostname | tr -d '\n') --server int.proxy.edgescale.org \
	    --localcacert /etc/ssl/private/edgescale/certs/estrootca.pem
./k8s.sh
