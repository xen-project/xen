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

XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror
CFLAGS  += $(CFLAGS_libxenstore)
CPPFLAGS += -DXEN_SCRIPT_DIR="\"$(XEN_SCRIPT_DIR)\""
LDLIBS  += $(LDLIBS_libxenstore)

.PHONY: all
all: build

.PHONY: build
build: xenbackendd

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) xenbackendd $(DESTDIR)$(sbindir)

.PHONY: clean
clean:
	$(RM) *.a *.so *.o $(DEPS) xenbackendd _paths.h

.PHONY: distclean
distclean: clean

xenbackendd.o: _paths.h
xenbackendd: xenbackendd.o
	$(CC) $(LDFLAGS) $< -o $@ $(LDLIBS) $(APPEND_LDFLAGS)

genpath-target = $(call buildmakevars2header,_paths.h)
$(eval $(genpath-target))

-include $(DEPS)
