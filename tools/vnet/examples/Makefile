# -*- mode: Makefile; -*-
#============================================================================

XEN_SCRIPT_DIR:=/etc/xen/scripts

.PHONY: all install clean

all:

install:
	install -m 0755 -d $(DESTDIR)$(XEN_SCRIPT_DIR)
	install -m 0554 network-vnet $(DESTDIR)$(XEN_SCRIPT_DIR)
	install -m 0554 vnet-insert $(DESTDIR)$(XEN_SCRIPT_DIR)

clean: