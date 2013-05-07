# Copyright (C) HP Labs, Palo Alto and Fort Collins, 2005
# Author: Diwaker Gupta <diwaker.gupta@hp.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; under version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror
CFLAGS  += $(CFLAGS_libxenctrl)
LDLIBS  += $(LDLIBS_libxenctrl)

SCRIPTS = xenmon.py

.PHONY: all
all: build

.PHONY: build
build: xentrace_setmask xenbaked

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) xenbaked $(DESTDIR)$(SBINDIR)/xenbaked
	$(INSTALL_PROG) xentrace_setmask  $(DESTDIR)$(SBINDIR)/xentrace_setmask
	$(INSTALL_PROG) xenmon.py  $(DESTDIR)$(SBINDIR)/xenmon.py
	$(INSTALL_DIR) $(DESTDIR)$(DOCDIR)
	$(INSTALL_DATA) README $(DESTDIR)$(DOCDIR)/README.xenmon

.PHONY: clean
clean:
	$(RM) -f $(DEPS)
	$(RM) -f xenbaked xenbaked.o
	$(RM) -f xentrace_setmask setmask.o

xenbaked: xenbaked.o Makefile
	$(CC) $(LDFLAGS) $< -o $@ $(LDLIBS) $(APPEND_LDFLAGS)

xentrace_setmask: setmask.o Makefile
	$(CC) $(LDFLAGS) $< -o $@ $(LDLIBS) $(APPEND_LDFLAGS)

-include $(DEPS)
