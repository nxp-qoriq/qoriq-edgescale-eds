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
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/etc/init.d
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/etc/rc3.d
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/etc/rc5.d
	sudo cp -r edgescale-version $(INSTALL_DIR)/etc/
	sudo cp -r edgescale $(INSTALL_DIR)/etc/init.d/
	sudo ln -s ../init.d/edgescale $(INSTALL_DIR)/etc/rc3.d/S09edgescale
	sudo ln -s ../init.d/edgescale $(INSTALL_DIR)/etc/rc5.d/S09edgescale


.PHONY: clean install
