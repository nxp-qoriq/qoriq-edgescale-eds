#####################################
#
# Copyright 2017 NXP
#
#####################################

INSTALL_DIR ?= /
INSTALL ?= install

all:
	go get github.com/laurentluce/est-client-go
	env GOOS=linux GOARCH=arm64 go build --ldflags="-w -s" cert-agent.go

clean:
	rm -f cert-agent

install:
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/usr/local/bin
	sudo cp -r cert-agent $(INSTALL_DIR)/usr/local/bin/
