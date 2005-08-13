# Copyright (C) International Business Machines Corp., 2005
# Author: Josh Triplett <josht@us.ibm.com>
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

ifneq ($(XENSTAT_VM_TOP),y)
all install vm-top:
else

INSTALL         = install
INSTALL_PROG    = $(INSTALL) -m0755 -D
INSTALL_DATA    = $(INSTALL) -m0644 -D

prefix=/usr
mandir=$(prefix)/share/man
man1dir=$(mandir)/man1
sbindir=$(prefix)/sbin

CFLAGS += -DGCC_PRINTF -Wall -Werror -I$(XEN_LIBXENSTAT)
LDFLAGS += -L$(XEN_LIBXENSTAT) -lxenstat -lcurses

all: vm-top

vm-top: vm-top.o

install: vm-top vm-top.1
	$(INSTALL_PROG) vm-top $(DESTDIR)$(sbindir)/vm-top
	$(INSTALL_DATA) vm-top.1 $(DESTDIR)$(man1dir)/vm-top.1

endif

clean:
	rm -f vm-top vm-top.o
