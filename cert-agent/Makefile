#####################################
#
# Copyright 2017-2018 NXP
#
#####################################

INSTALL_DIR ?= /
INSTALL ?= install

SECURE_OBJ_PATH ?= $(shell pwd)/../../secure_obj/securekey_lib/out/export
OPENSSL_PATH ?= $(shell pwd)/../../openssl
OPTEE_CLIENT_EXPORT ?= $(shell pwd)/../../optee_client/out/libteec

ARCH ?= arm64
CROSS_COMPILE ?= aarch64-linux-gnu-
CC := ${CROSS_COMPILE}gcc
CGO_LDFLAGS += -L${SECURE_OBJ_PATH}/lib -L${OPENSSL_PATH}/lib -L${OPTEE_CLIENT_EXPORT}
CGO_CFLAGS += -I${SECURE_OBJ_PATH}/include -I${OPENSSL_PATH}/include
GOBUILDTAGS ?= default


all:
	go get github.com/edgeiot/est-client-go
	env CGO_ENABLED=1 GOOS=linux GOARCH=${ARCH} CC=${CC} CGO_CFLAGS="${CGO_CFLAGS}" CGO_LDFLAGS="${CGO_LDFLAGS}" go build -o cert-agent --ldflags="-w -s" --tags "${GOBUILDTAGS}"

clean:
	rm -f cert-agent

install:
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/usr/local/edgescale/bin
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/usr/local/edgescale/conf
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/usr/local/edgescale/doc
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/usr/local/edgescale/log
	sudo cp -r cert-agent $(INSTALL_DIR)/usr/local/edgescale/bin
