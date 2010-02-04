XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

# Xen script dir and scripts to go there.
XEN_SCRIPTS =
XEN_SCRIPTS += block
XEN_SCRIPTS += vif-bridge
XEN_SCRIPTS += vif-ip

XEN_SCRIPT_DATA =

.PHONY: all
all:

.PHONY: build
build:

.PHONY: install
install: all install-scripts

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

.PHONY: clean
clean:
