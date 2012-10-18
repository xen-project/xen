XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

HOTPLUGPATH="hotplugpath.sh"

# OS-independent hotplug scripts go in this directory

# Xen scripts to go there.
XEN_SCRIPTS =
XEN_SCRIPT_DATA = $(HOTPLUGPATH)

genpath-target = $(call buildmakevars2file,$(HOTPLUGPATH))
$(eval $(genpath-target))

.PHONY: all
all: build

.PHONY: build
build: genpath

.PHONY: install
install: all install-scripts

.PHONY: install-scripts
install-scripts: build
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
	rm -f $(HOTPLUGPATH)
