#####################################
#
# Copyright 2017-2018 NXP
#
#####################################

INSTALL_DIR ?= /
INSTALL ?= install

clean:

install:
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/etc
	sudo cp -r edgescale-version $(INSTALL_DIR)/etc/


.PHONY: clean install
