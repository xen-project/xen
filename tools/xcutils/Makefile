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

CFLAGS_xc_restore := $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest)
CFLAGS_xc_save    := $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest) $(CFLAGS_libxenstore)
CFLAGS_readnotes  := $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest)
CFLAGS_lsevtchn   := $(CFLAGS_libxenctrl)

LDLIBS_xc_restore := $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest)
LDLIBS_xc_save    := $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore)
LDLIBS_readnotes  := $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest)
LDLIBS_lsevtchn   := $(LDLIBS_libxenctrl)

.PHONY: all
all: build

.PHONY: build
build: $(PROGRAMS)

%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGS_$*) -c $^ -o $@

$(PROGRAMS): %: %.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) $(LDLIBS_$*) -o $@

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(PRIVATE_BINDIR)
	$(INSTALL_PROG) $(PROGRAMS) $(DESTDIR)$(PRIVATE_BINDIR)


.PHONY: clean
clean:
	$(RM) *.o $(PROGRAMS)
	$(RM) $(DEPS)

-include $(DEPS)
