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

XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror
CFLAGS  += -I $(XEN_XC)
CFLAGS  += -I $(XEN_LIBXC)
LDFLAGS += -L $(XEN_LIBXC)

BIN = xentrace_setmask xenbaked
SCRIPTS = xenmon.py

.PHONY: all
all: build

.PHONY: build
build: $(BIN)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) xenbaked $(DESTDIR)$(SBINDIR)/xenbaked
	$(INSTALL_PROG) xentrace_setmask  $(DESTDIR)$(SBINDIR)/xentrace_setmask
	$(INSTALL_PROG) xenmon.py  $(DESTDIR)$(SBINDIR)/xenmon.py

.PHONY: clean
clean:
	rm -f $(BIN)


%: %.c Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -lxenctrl -o $@ $<
xentrace_%: %.c Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -lxenctrl -o $@ $<
