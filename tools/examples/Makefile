XEN_ROOT = ../../
include $(XEN_ROOT)/tools/Rules.mk

INSTALL		= install
INSTALL_DIR	= $(INSTALL) -d -m0755
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DATA	= $(INSTALL) -m0644

# Init scripts.
XEND_INITD = init.d/xend
XENDOMAINS_INITD = init.d/xendomains
XENDOMAINS_SYSCONFIG = init.d/sysconfig.xendomains

# Xen configuration dir and configs to go there.
XEN_CONFIG_DIR = /etc/xen
XEN_CONFIGS = xend-config.sxp
XEN_CONFIGS += xmexample1 
XEN_CONFIGS += xmexample2
XEN_CONFIGS += xmexample.vmx

# Xen script dir and scripts to go there.
XEN_SCRIPT_DIR = /etc/xen/scripts
XEN_SCRIPTS = network-bridge vif-bridge
XEN_SCRIPTS += network-route vif-route
XEN_SCRIPTS += network-nat vif-nat
XEN_SCRIPTS += block
XEN_SCRIPTS += block-enbd block-nbd
XEN_SCRIPTS += xen-hotplug-common.sh xen-network-common.sh vif-common.sh
XEN_SCRIPTS += block-common.sh

XEN_HOTPLUG_DIR = /etc/hotplug
XEN_HOTPLUG_SCRIPTS = xen-backend.agent

UDEV_RULES_DIR = /etc/udev/rules.d
UDEV_RULES = xen-backend.rules

DI = $(shell readlink -f $(DISTDIR))
DE = $(shell readlink -f $(DESTDIR))
ifeq ($(findstring $(DI),$(DE)),$(DI))
HOTPLUGS=install-hotplug install-udev
else
ifeq ($(shell [ -x /sbin/udev ] && [ ! -z `udev -V` ] && [ `/sbin/udev -V` -ge 059 ] && echo 1),1)
HOTPLUGS=install-udev
else
HOTPLUGS=install-hotplug
endif
endif

all:
build:

install: all install-initd install-configs install-scripts $(HOTPLUGS)

install-initd:
	[ -d $(DESTDIR)/etc/init.d ] || $(INSTALL_DIR) $(DESTDIR)/etc/init.d
	[ -d $(DESTDIR)/etc/sysconfig ] || $(INSTALL_DIR) $(DESTDIR)/etc/sysconfig
	$(INSTALL_PROG) $(XEND_INITD) $(DESTDIR)/etc/init.d
	$(INSTALL_PROG) $(XENDOMAINS_INITD) $(DESTDIR)/etc/init.d
	$(INSTALL_PROG) $(XENDOMAINS_SYSCONFIG) $(DESTDIR)/etc/sysconfig/xendomains

install-configs: $(XEN_CONFIGS)
	[ -d $(DESTDIR)$(XEN_CONFIG_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_CONFIG_DIR)
	[ -d $(DESTDIR)$(XEN_CONFIG_DIR)/auto ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_CONFIG_DIR)/auto
	for i in $(XEN_CONFIGS); \
	    do [ -e $(DESTDIR)$(XEN_CONFIG_DIR)/$$i ] || \
	    $(INSTALL_DATA) $$i $(DESTDIR)$(XEN_CONFIG_DIR); \
	done

install-scripts:
	[ -d $(DESTDIR)$(XEN_SCRIPT_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_SCRIPT_DIR)
	for i in $(XEN_SCRIPTS); \
	    do \
	    $(INSTALL_PROG) $$i $(DESTDIR)$(XEN_SCRIPT_DIR); \
	done

install-hotplug:
	[ -d $(DESTDIR)$(XEN_HOTPLUG_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_HOTPLUG_DIR)
	for i in $(XEN_HOTPLUG_SCRIPTS); \
	    do \
	    $(INSTALL_PROG) $$i $(DESTDIR)$(XEN_HOTPLUG_DIR); \
	done

install-udev:
	[ -d $(DESTDIR)$(UDEV_RULES_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(UDEV_RULES_DIR)
	for i in $(UDEV_RULES); \
	    do \
	    $(INSTALL_PROG) $$i $(DESTDIR)$(UDEV_RULES_DIR); \
	done

clean:
