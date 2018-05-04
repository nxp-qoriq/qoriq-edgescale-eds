#####################################
#
# Copyright 2017 NXP
#
#####################################

INSTALL_DIR ?= /
INSTALL ?= install

GOROOT ?= $(HOME)/go
GOPATH ?= $(HOME)/gopathdir
GOFILE ?= go1.8.5.linux-amd64.tar.gz

TARGETS := cert-agent mq-agent startup etc

.PHONY: $(TARGETS) clean all install


all: goenv
	for dir in $(TARGETS);\
	do \
		echo build target $$dir; \
		$(MAKE) -C $$dir GOROOT=$(GOROOT) GOPATH=$(GOPATH) PATH=$(GOROOT)/bin:$(PATH) || exit 1; \
	done


install:
	for dir in $(TARGETS);\
	do \
		echo install target $$dir; \
		$(MAKE) -C $$dir install || exit 1; \
	done

$(TARGETS):
	@echo build $@
	$(MAKE) -C $@ 

goenv:
	if [ ! -f $(GOROOT)/bin/go ]; then  \
		wget -c https://redirector.gvt1.com/edgedl/go/$(GOFILE); \
		tar -C $(HOME) -xzf $(GOFILE); \
	fi
	usr=`whoami`; \

clean:
	for dir in $(TARGETS);\
	do \
		echo clean target $$dir; \
		$(MAKE) -C $$dir clean; \
	done

