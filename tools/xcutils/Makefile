#
# tools/xcutils/Makefile
#
# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.
#
# Copyright (C) 2005 by Christian Limpach
#

XEN_ROOT	= $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

PROGRAMS = readnotes lsevtchn

CFLAGS += -Werror

CFLAGS_readnotes.o  := $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest)
CFLAGS_lsevtchn.o   := $(CFLAGS_libxenctrl)

.PHONY: all
all: build

.PHONY: build
build: $(PROGRAMS)

readnotes: readnotes.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(APPEND_LDFLAGS)

lsevtchn: lsevtchn.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(PRIVATE_BINDIR)
	$(INSTALL_PROG) $(PROGRAMS) $(DESTDIR)$(PRIVATE_BINDIR)


.PHONY: clean
clean:
	$(RM) *.o $(PROGRAMS)
	$(RM) $(DEPS)

-include $(DEPS)
