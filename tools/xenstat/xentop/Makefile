# Copyright (C) International Business Machines Corp., 2005
# Author: Josh Triplett <josh@kernel.org>
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; under version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk

ifneq ($(XENSTAT_XENTOP),y)
.PHONY: all install xentop
all install xentop:
else

prefix=/usr
mandir=$(prefix)/share/man
man1dir=$(mandir)/man1
sbindir=$(prefix)/sbin

CFLAGS += -DGCC_PRINTF -Wall -Werror -I$(XEN_LIBXENSTAT)
LDFLAGS += -L$(XEN_LIBXENSTAT)
LDLIBS += -lxenstat $(CURSES_LIBS) $(SOCKET_LIBS)
CFLAGS += -DHOST_$(XEN_OS)

.PHONY: all
all: xentop

.PHONY: install
install: xentop xentop.1
	$(INSTALL_PROG) xentop $(DESTDIR)$(sbindir)/xentop
	$(INSTALL_DIR) $(DESTDIR)$(man1dir)
	$(INSTALL_DATA) xentop.1 $(DESTDIR)$(man1dir)/xentop.1

endif

.PHONY: clean
clean:
	rm -f xentop xentop.o
