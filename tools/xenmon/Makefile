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
CFLAGS  += $(CFLAGS_libxenevtchn)
CFLAGS  += $(CFLAGS_libxenctrl)
LDLIBS  += $(LDLIBS_libxenctrl)
LDLIBS  += $(LDLIBS_libxenevtchn)

SCRIPTS = xenmon.py

.PHONY: all
all: build

.PHONY: build
build: xentrace_setmask xenbaked

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) xenbaked $(DESTDIR)$(sbindir)/xenbaked
	$(INSTALL_PROG) xentrace_setmask  $(DESTDIR)$(sbindir)/xentrace_setmask
	$(INSTALL_PROG) xenmon.py  $(DESTDIR)$(sbindir)/xenmon.py

.PHONY: clean
clean:
	$(RM) -f $(DEPS)
	$(RM) -f xenbaked xenbaked.o
	$(RM) -f xentrace_setmask setmask.o

.PHONY: distclean
distclean: clean

xenbaked: xenbaked.o Makefile
	$(CC) $(LDFLAGS) $< -o $@ $(LDLIBS) $(APPEND_LDFLAGS)

xentrace_setmask: setmask.o Makefile
	$(CC) $(LDFLAGS) $< -o $@ $(LDLIBS) $(APPEND_LDFLAGS)

-include $(DEPS)
