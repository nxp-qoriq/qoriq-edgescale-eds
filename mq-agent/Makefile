INSTALL_DIR ?= /
INSTALL ?= install
ARCH ?= arm64

all:
	go get github.com/sirupsen/logrus
	go get github.com/yosssi/gmq/mqtt
	go get bitbucket.org/bertimus9/systemstat
	env GOOS=linux GOARCH=$(ARCH) go build --ldflags="-w -s" mq-agent.go device-log.go

clean:
	rm -f mq-agent

install:
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/usr/local/bin
	sudo cp -r mq-agent $(INSTALL_DIR)/usr/local/bin/
