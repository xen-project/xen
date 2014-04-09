XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

# Init scripts.
XENDOMAINS_INITD = init.d/xendomains
XENDOMAINS_SYSCONFIG = init.d/sysconfig.xendomains

XENCOMMONS_INITD = init.d/xencommons
XENCOMMONS_SYSCONFIG = init.d/sysconfig.xencommons

# Xen script dir and scripts to go there.
XEN_SCRIPTS = vif-bridge
XEN_SCRIPTS += vif-route
XEN_SCRIPTS += vif-nat
XEN_SCRIPTS += vif-openvswitch
XEN_SCRIPTS += vif2
XEN_SCRIPTS += vif-setup
XEN_SCRIPTS += block
XEN_SCRIPTS += block-enbd block-nbd
XEN_SCRIPTS-$(CONFIG_BLKTAP1) += blktap
XEN_SCRIPTS += xen-hotplug-cleanup
XEN_SCRIPTS += external-device-migrate
XEN_SCRIPTS += vscsi
XEN_SCRIPTS += block-iscsi
XEN_SCRIPTS += $(XEN_SCRIPTS-y)

XEN_SCRIPT_DATA = xen-script-common.sh locking.sh logging.sh
XEN_SCRIPT_DATA += xen-hotplug-common.sh xen-network-common.sh vif-common.sh
XEN_SCRIPT_DATA += block-common.sh

UDEV_RULES_DIR = $(CONFIG_DIR)/udev
UDEV_RULES = xen-backend.rules $(UDEV_RULES-y)

.PHONY: all
all:

.PHONY: build
build:

.PHONY: install
install: all install-initd install-scripts install-udev

# See docs/misc/distro_mapping.txt for INITD_DIR location
.PHONY: install-initd
install-initd:
	[ -d $(DESTDIR)$(INITD_DIR) ] || $(INSTALL_DIR) $(DESTDIR)$(INITD_DIR)
	[ -d $(DESTDIR)$(SYSCONFIG_DIR) ] || $(INSTALL_DIR) $(DESTDIR)$(SYSCONFIG_DIR)
	$(INSTALL_PROG) $(XENDOMAINS_INITD) $(DESTDIR)$(INITD_DIR)
	$(INSTALL_DATA) $(XENDOMAINS_SYSCONFIG) $(DESTDIR)$(SYSCONFIG_DIR)/xendomains
	$(INSTALL_PROG) $(XENCOMMONS_INITD) $(DESTDIR)$(INITD_DIR)
	$(INSTALL_DATA) $(XENCOMMONS_SYSCONFIG) $(DESTDIR)$(SYSCONFIG_DIR)/xencommons
	$(INSTALL_PROG) init.d/xen-watchdog $(DESTDIR)$(INITD_DIR)

.PHONY: install-scripts
install-scripts:
	[ -d $(DESTDIR)$(XEN_SCRIPT_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_SCRIPT_DIR)
	set -e; for i in $(XEN_SCRIPTS); \
	    do \
	    $(INSTALL_PROG) $$i $(DESTDIR)$(XEN_SCRIPT_DIR); \
	done
	set -e; for i in $(XEN_SCRIPT_DATA); \
	    do \
	    $(INSTALL_DATA) $$i $(DESTDIR)$(XEN_SCRIPT_DIR); \
	done

.PHONY: install-udev
install-udev:
	[ -d $(DESTDIR)$(UDEV_RULES_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(UDEV_RULES_DIR)/rules.d
	set -e; for i in $(UDEV_RULES); \
	    do \
	    $(INSTALL_DATA) $$i $(DESTDIR)$(UDEV_RULES_DIR)/rules.d; \
	done

.PHONY: clean
clean:
