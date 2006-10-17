# -*- mode: Makefile; -*-
#============================================================================
XEN_ROOT        = ../../..
include $(XEN_ROOT)/tools/Rules.mk

SBIN_DIR        = $(DESTDIR)/usr/sbin

.PHONY: all
all:

.PHONY: install
install:
	$(INSTALL_DIR) $(SBIN_DIR)
	$(INSTALL_PROG) vn $(SBIN_DIR)

.PHONY: clean
clean:
