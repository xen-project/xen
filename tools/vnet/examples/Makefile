# -*- mode: Makefile; -*-
#============================================================================

XEN_SCRIPT_DIR:=/etc/xen/scripts

all:

install:
	install -m 0755 -d $(prefix)$(XEN_SCRIPT_DIR)
	install -m 0554 network-vnet $(prefix)$(XEN_SCRIPT_DIR)

clean: