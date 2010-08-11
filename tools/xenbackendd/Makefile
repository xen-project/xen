# Copyright (c) 2009 Advanced Micro Devices, Inc.
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
CFLAGS  += $(CFLAGS_libxenstore)
CPPFLAGS += -DXEN_SCRIPT_DIR="\"$(XEN_SCRIPT_DIR)\""
LDLIBS  += $(LDLIBS_libxenstore)

SBIN = xenbackendd

.PHONY: all
all: build

.PHONY: build
build: $(SBIN)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) xenbackendd $(DESTDIR)$(SBINDIR)

.PHONY: clean
clean:
	rm -f $(SBIN) $(DEPS)


%: %.c Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< -o $@ $(LDLIBS)

-include $(DEPS)
