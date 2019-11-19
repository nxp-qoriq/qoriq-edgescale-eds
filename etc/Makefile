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
	$(INSTALL) -d --mode 755 $(INSTALL_DIR)/usr/local/edgescale/conf

	if [ -n "$(ES_DOMAIN_SUFFIX)" ]; then \
	  sed -i "s,api.*,api: https://api.$(ES_DOMAIN_SUFFIX)/v1," config.yml; \
	fi

	if [ -n "$(ES_CERTIFICATE_PATH)" ]; then \
	  $(INSTALL) -d --mode 755 $(INSTALL_DIR)/usr/local/share/ca-certificates; \
	  sudo cp -fr $(ES_CERTIFICATE_PATH)/* $(INSTALL_DIR)/usr/local/share/ca-certificates; \
	fi

	sudo cp -r config.yml $(INSTALL_DIR)/usr/local/edgescale/conf
	sudo cp -r edgescale-version $(INSTALL_DIR)/usr/local/edgescale/conf
	sudo cp -r edgescale $(INSTALL_DIR)/etc/init.d/
	sudo ln -sf ../init.d/edgescale $(INSTALL_DIR)/etc/rc3.d/S09edgescale
	sudo ln -sf ../init.d/edgescale $(INSTALL_DIR)/etc/rc5.d/S09edgescale


.PHONY: clean install
