# -*- mode: Makefile; -*-
#============================================================================

INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

SBIN_DIR        = $(DESTDIR)/usr/sbin

.PHONY: all
all:

.PHONY: install
install:
	$(INSTALL_DIR) $(SBIN_DIR)
	$(INSTALL_PROG) vn $(SBIN_DIR)

.PHONY: clean
clean:
