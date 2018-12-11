#####################################
#
# Copyright 2017-2018 NXP
#
#####################################

INSTALL_DIR ?= /
INSTALL ?= install
ARCH ?= arm64
GOBUILDTAGS ?= default
OPENSSL_PATH ?= $(shell pwd)/../../openssl
CROSS_COMPILE ?= aarch64-linux-gnu-
CC := ${CROSS_COMPILE}gcc
CGO_LDFLAGS += -L${OPENSSL_PATH}/lib
CGO_CFLAGS += -I${OPENSSL_PATH}/include

all:
	rm -rf ${GOPATH}/src/golang.org/x/sys
	rm -rf ${GOPATH}/src/golang.org/x/crypto
	git clone https://github.com/golang/sys  ${GOPATH}/src/golang.org/x/sys
	git clone https://github.com/golang/crypto ${GOPATH}/src/golang.org/x/crypto
	go get github.com/sirupsen/logrus
	go get github.com/sigma/systemstat
	go get github.com/eclipse/paho.mqtt.golang
	env GOOS=linux GOARCH=$(ARCH) CGO_ENABLED=1  CC=${CC} CGO_CFLAGS="${CGO_CFLAGS}" CGO_LDFLAGS="${CGO_LDFLAGS}"  go build --ldflags="-w -s" --tags "${GOBUILDTAGS}"

clean:
	rm -f mq-agent

install:
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/usr/local/bin
	sudo cp -r mq-agent $(INSTALL_DIR)/usr/local/bin/
