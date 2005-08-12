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

ifneq (,$(shell [ -e /usr/include/curses.h ] || echo no))
all vm-top:
	@echo "***********************************************************"
	@echo "WARNING: Install ncurses to build vm-top."
	@echo "***********************************************************"
else

XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk

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

endif

install: vm-top vm-top.1
	[ -f vm-top ] && $(INSTALL_PROG) vm-top $(DESTDIR)$(sbindir)/vm-top
	[ -f vm-top.1 ] && \
	    $(INSTALL_DATA) vm-top.1 $(DESTDIR)$(man1dir)/vm-top.1

clean:
	rm -f vm-top vm-top.o
