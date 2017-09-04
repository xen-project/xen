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

XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

ifneq ($(XENSTAT_XENTOP),y)
.PHONY: all install xentop uninstall
all install xentop uninstall:
else

CFLAGS += -DGCC_PRINTF -Werror $(CFLAGS_libxenstat)
LDLIBS += $(LDLIBS_libxenstat) $(CURSES_LIBS) $(TINFO_LIBS) $(SOCKET_LIBS) -lm
CFLAGS += -DHOST_$(XEN_OS)

# Include configure output (config.h)
CFLAGS += -include $(XEN_ROOT)/tools/config.h
LDFLAGS += $(APPEND_LDFLAGS)

.PHONY: all
all: xentop

.PHONY: install
install: xentop
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) xentop $(DESTDIR)$(sbindir)/xentop

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(sbindir)/xentop

endif

.PHONY: clean
clean:
	rm -f xentop xentop.o $(DEPS_RM)

.PHONY: distclean
distclean: clean

-include $(DEPS_INCLUDE)
