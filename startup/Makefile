#####################################
#
# Copyright 2017-2018 NXP
#
#####################################

INSTALL_DIR ?= /
INSTALL ?= install

clean:

install:
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/usr/local/bin
	sudo cp -r env.sh $(INSTALL_DIR)/usr/local/bin/
	sudo cp -r startup.sh $(INSTALL_DIR)/usr/local/bin/
	sudo cp -r ota-updateSet $(INSTALL_DIR)/usr/local/bin/
	sudo cp -r ota-statuscheck $(INSTALL_DIR)/usr/local/bin/
	sudo cp -f mmc-check.sh $(INSTALL_DIR)/usr/local/bin/
	sudo cp -f factory_reset.sh $(INSTALL_DIR)/usr/local/bin/

.PHONY: clean install
