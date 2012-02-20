XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

# Init scripts.
XEND_INITD = init.d/xend
XENDOMAINS_INITD = init.d/xendomains
XENDOMAINS_SYSCONFIG = init.d/sysconfig.xendomains

# Xen configuration dir and configs to go there.
XEN_READMES = README
XEN_READMES += README.incompatibilities
XEN_CONFIGS = xend-config.sxp
XEN_CONFIGS += xm-config.xml
XEN_CONFIGS += xmexample1 
XEN_CONFIGS += xmexample2
XEN_CONFIGS += xmexample3
XEN_CONFIGS += xmexample.hvm
XEN_CONFIGS += xmexample.hvm-stubdom
XEN_CONFIGS += xmexample.pv-grub
XEN_CONFIGS += xmexample.nbd
XEN_CONFIGS += xmexample.vti
XEN_CONFIGS += xlexample.hvm
XEN_CONFIGS += xlexample.pvlinux
XEN_CONFIGS += xend-pci-quirks.sxp
XEN_CONFIGS += xend-pci-permissive.sxp
XEN_CONFIGS += xl.conf
XEN_CONFIGS += cpupool

.PHONY: all
all:

.PHONY: build
build:

.PHONY: install
install: all install-readmes install-configs $(HOTPLUGS)

.PHONY: install-readmes
install-readmes:
	[ -d $(DESTDIR)$(XEN_CONFIG_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_CONFIG_DIR)
	set -e; for i in $(XEN_READMES); \
	    do [ -e $(DESTDIR)$(XEN_CONFIG_DIR)/$$i ] || \
	    $(INSTALL_DATA) $$i $(DESTDIR)$(XEN_CONFIG_DIR); \
	done

.PHONY: install-configs
install-configs: $(XEN_CONFIGS)
	[ -d $(DESTDIR)$(XEN_CONFIG_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_CONFIG_DIR)
	[ -d $(DESTDIR)$(XEN_CONFIG_DIR)/auto ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_CONFIG_DIR)/auto
	set -e; for i in $(XEN_CONFIGS); \
	    do [ -e $(DESTDIR)$(XEN_CONFIG_DIR)/$$i ] || \
	    $(INSTALL_DATA) $$i $(DESTDIR)$(XEN_CONFIG_DIR); \
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
	    $(INSTALL_DATA) $$i $(DESTDIR)$(UDEV_RULES_DIR); \
	    ln -sf ../$$i $(DESTDIR)$(UDEV_RULES_DIR)/rules.d; \
	done

.PHONY: clean
clean:
