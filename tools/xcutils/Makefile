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

PROGRAMS = xc_restore xc_save readnotes lsevtchn

CFLAGS += -Werror

CFLAGS_xc_restore.o := $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest)
CFLAGS_xc_save.o    := $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest) $(CFLAGS_libxenstore)
CFLAGS_readnotes.o  := $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest)
CFLAGS_lsevtchn.o   := $(CFLAGS_libxenctrl)

.PHONY: all
all: build

.PHONY: build
build: $(PROGRAMS)

xc_restore: xc_restore.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(APPEND_LDFLAGS)

xc_save: xc_save.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore) $(APPEND_LDFLAGS)

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
