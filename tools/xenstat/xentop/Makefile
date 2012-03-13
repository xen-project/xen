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
.PHONY: all install xentop
all install xentop:
else

CFLAGS += -DGCC_PRINTF -Wall -Werror $(CFLAGS_libxenstat)
LDLIBS += $(LDLIBS_libxenstat) $(CURSES_LIBS) $(SOCKET_LIBS)
CFLAGS += -DHOST_$(XEN_OS)

# Include configure output (config.h) to headers search path
CFLAGS += -I$(XEN_ROOT)/tools

.PHONY: all
all: xentop

.PHONY: install
install: xentop xentop.1
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) xentop $(DESTDIR)$(SBINDIR)/xentop
	$(INSTALL_DIR) $(DESTDIR)$(MAN1DIR)
	$(INSTALL_DATA) xentop.1 $(DESTDIR)$(MAN1DIR)/xentop.1

endif

.PHONY: clean
clean:
	rm -f xentop xentop.o $(DEPS)

-include $(DEPS)
