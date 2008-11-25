XEN_ROOT = ../../../
include $(XEN_ROOT)/tools/Rules.mk

# OS-independent hotplug scripts go in this directory

# Xen configuration dir and configs to go there.
XEN_CONFIG_DIR = /etc/xen

# Xen script dir and scripts to go there.
XEN_SCRIPT_DIR = /etc/xen/scripts
XEN_SCRIPTS =
XEN_SCRIPT_DATA =

.PHONY: all
all:

.PHONY: build
build:

.PHONY: install
install: all install-scripts

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

.PHONY: clean
clean:
