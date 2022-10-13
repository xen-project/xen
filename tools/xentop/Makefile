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

XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -DGCC_PRINTF $(CFLAGS_libxenstat)
LDLIBS += $(LDLIBS_libxenstat) $(CURSES_LIBS) $(TINFO_LIBS) $(SOCKET_LIBS) -lm
CFLAGS += -DHOST_$(XEN_OS)

# Include configure output (config.h)
CFLAGS += -include $(XEN_ROOT)/tools/config.h

TARGETS := xentop

.PHONY: all
all: $(TARGETS)

xentop: xentop.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS) $(APPEND_LDFLAGS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) $(TARGETS) $(DESTDIR)$(sbindir)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(sbindir)/xentop

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) $(DEPS_RM)

.PHONY: distclean
distclean: clean

-include $(DEPS_INCLUDE)
