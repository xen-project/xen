XEN_ROOT = ../../../
include $(XEN_ROOT)/tools/Rules.mk

# Xen configuration dir and configs to go there.
XEN_CONFIG_DIR = $(PREFIX)/etc/xen

# Xen script dir and scripts to go there.
XEN_SCRIPT_DIR = $(PREFIX)/etc/xen/scripts
XEN_SCRIPTS =
XEN_SCRIPTS += block-nbsd
XEN_SCRIPTS += hvm-nbsd
XEN_SCRIPTS += netbsd1-nbsd
XEN_SCRIPTS += qemu-ifup-nbsd
XEN_SCRIPTS += vif-bridge-nbsd
XEN_SCRIPTS += vif-ip-nbsd

XEN_SCRIPT_DATA =

.PHONY: all
all:

.PHONY: build
build:

.PHONY: install
install: all install-scripts

.PHONY: install-scripts
install-scripts:
	$(INSTALL_DATA_DIR) $(DESTDIR)$(XEN_SCRIPT_DIR)
	set -e; for i in $(XEN_SCRIPTS); \
	   do \
	   $(INSTALL_DATA) $$i $(DESTDIR)$(XEN_SCRIPT_DIR); \
	done
	set -e; for i in $(XEN_SCRIPT_DATA); \
	   do \
	   $(INSTALL_DATA) $$i $(DESTDIR)$(XEN_SCRIPT_DIR); \
	done

.PHONY: clean
clean:
