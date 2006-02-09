# -*- mode: Makefile; -*-
#============================================================================

INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

XEN_SCRIPT_DIR  = $(DESTDIR)/etc/xen/scripts

.PHONY: all install clean

all:

install:
	$(INSTALL_DIR) $(XEN_SCRIPT_DIR)
	$(INSTALL_PROG) network-vnet $(XEN_SCRIPT_DIR)
	$(INSTALL_PROG) vnet-insert $(XEN_SCRIPT_DIR)

clean: