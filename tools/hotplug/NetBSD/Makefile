XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

# Xen script dir and scripts to go there.
XEN_SCRIPTS =
XEN_SCRIPTS += block
XEN_SCRIPTS += vif-bridge
XEN_SCRIPTS += vif-ip

XEN_SCRIPT_DATA =
XEN_RCD_PROG = rc.d/xencommons rc.d/xendomains rc.d/xen-watchdog

.PHONY: all
all:

.PHONY: build
build:

.PHONY: install
install: install-scripts install-rcd

.PHONY: install-scripts
install-scripts:
	$(INSTALL_DIR) $(DESTDIR)$(XEN_SCRIPT_DIR)
	set -e; for i in $(XEN_SCRIPTS); \
	   do \
	   $(INSTALL_PROG) $$i $(DESTDIR)$(XEN_SCRIPT_DIR); \
	done
	set -e; for i in $(XEN_SCRIPT_DATA); \
	   do \
	   $(INSTALL_DATA) $$i $(DESTDIR)$(XEN_SCRIPT_DIR); \
	done

.PHONY: install-rcd
install-rcd:
	$(INSTALL_DIR) $(DESTDIR)$(INITD_DIR)
	set -e; for i in $(XEN_RCD_PROG); \
	   do \
	   $(INSTALL_PROG) $$i $(DESTDIR)$(INITD_DIR); \
	done
	$(INSTALL_DATA) ../common/hotplugpath.sh $(DESTDIR)$(INITD_DIR)/xen-hotplugpath.sh

.PHONY: clean
clean:
