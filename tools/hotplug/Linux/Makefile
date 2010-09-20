XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

# Init scripts.
XEND_INITD = init.d/xend
XENDOMAINS_INITD = init.d/xendomains
XENDOMAINS_SYSCONFIG = init.d/sysconfig.xendomains

XENCOMMONS_INITD = init.d/xencommons
XENCOMMONS_SYSCONFIG = init.d/sysconfig.xencommons

# Xen script dir and scripts to go there.
XEN_SCRIPTS = network-bridge vif-bridge
XEN_SCRIPTS += network-route vif-route
XEN_SCRIPTS += network-nat vif-nat
XEN_SCRIPTS += vif2
XEN_SCRIPTS += vif-setup
XEN_SCRIPTS += block
XEN_SCRIPTS += block-enbd block-nbd
XEN_SCRIPTS += blktap
XEN_SCRIPTS += vtpm vtpm-delete
XEN_SCRIPTS += xen-hotplug-cleanup
XEN_SCRIPTS += external-device-migrate
XEN_SCRIPTS += vscsi
XEN_SCRIPT_DATA = xen-script-common.sh locking.sh logging.sh
XEN_SCRIPT_DATA += xen-hotplug-common.sh xen-network-common.sh vif-common.sh
XEN_SCRIPT_DATA += block-common.sh vtpm-common.sh vtpm-hotplug-common.sh
XEN_SCRIPT_DATA += vtpm-migration.sh vtpm-impl

XEN_HOTPLUG_DIR = $(CONFIG_DIR)/hotplug
XEN_HOTPLUG_SCRIPTS = xen-backend.agent

UDEVVER = 0
ifeq ($(shell [ -x /sbin/udevadm ] && echo 1),1)
UDEVVER = $(shell /sbin/udevadm info -V | sed -e 's/^[^0-9]* \([0-9]\{1,\}\)[^0-9]\{0,\}/\1/' )
endif
ifeq ($(shell [ -x /usr/bin/udevinfo ] && echo 1),1)
UDEVVER = $(shell /usr/bin/udevinfo -V | sed -e 's/^[^0-9]* \([0-9]\{1,\}\)[^0-9]\{0,\}/\1/' )
endif

UDEV_RULES_DIR = $(CONFIG_DIR)/udev
UDEV_RULES = xen-backend.rules xend.rules

DI = $(if $(DISTDIR),$(shell readlink -f $(DISTDIR)),)
DE = $(if $(DESTDIR),$(shell readlink -f $(DESTDIR)),)
ifeq ($(findstring $(DI),$(DE)),$(DI))
HOTPLUGS=install-hotplug install-udev
else
ifeq ($(shell [ $(UDEVVER) -ge 059 ] && echo 1),1)
HOTPLUGS=install-udev
else
HOTPLUGS=install-hotplug
endif
endif

.PHONY: all
all:

.PHONY: build
build:

.PHONY: install
install: all install-initd install-scripts $(HOTPLUGS)

# See docs/misc/distro_mapping.txt for INITD_DIR location
.PHONY: install-initd
install-initd:
	[ -d $(DESTDIR)$(INITD_DIR) ] || $(INSTALL_DIR) $(DESTDIR)$(INITD_DIR)
	[ -d $(DESTDIR)$(SYSCONFIG_DIR) ] || $(INSTALL_DIR) $(DESTDIR)$(SYSCONFIG_DIR)
	$(INSTALL_PROG) $(XEND_INITD) $(DESTDIR)$(INITD_DIR)
	$(INSTALL_PROG) $(XENDOMAINS_INITD) $(DESTDIR)$(INITD_DIR)
	$(INSTALL_PROG) $(XENDOMAINS_SYSCONFIG) $(DESTDIR)$(SYSCONFIG_DIR)/xendomains
	$(INSTALL_PROG) $(XENCOMMONS_INITD) $(DESTDIR)$(INITD_DIR)
	$(INSTALL_PROG) $(XENCOMMONS_SYSCONFIG) $(DESTDIR)$(SYSCONFIG_DIR)/xencommons
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

.PHONY: install-hotplug
install-hotplug:
	[ -d $(DESTDIR)$(XEN_HOTPLUG_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_HOTPLUG_DIR)
	set -e; for i in $(XEN_HOTPLUG_SCRIPTS); \
	    do \
	    $(INSTALL_PROG) $$i $(DESTDIR)$(XEN_HOTPLUG_DIR); \
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
