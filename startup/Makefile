#####################################
#
# Copyright 2017 NXP
#
#####################################

INSTALL_DIR ?= /
INSTALL ?= install

clean:

install:
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/usr/local/bin
	sudo cp -r env.sh $(INSTALL_DIR)/usr/local/bin/
	sudo cp -r startup.sh $(INSTALL_DIR)/usr/local/bin/


.PHONY: clean install
