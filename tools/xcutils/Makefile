#
# tools/xcutils/Makefile
#
# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.
#
# Copyright (C) 2005 by Christian Limpach
#

XEN_ROOT	= ../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror
CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest) $(CFLAGS_libxenstore)

PROGRAMS = xc_restore xc_save readnotes lsevtchn

LDLIBS   = $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore)

.PHONY: all
all: build

.PHONY: build
build: $(PROGRAMS)

$(PROGRAMS): %: %.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(PRIVATE_BINDIR)
	$(INSTALL_PROG) $(PROGRAMS) $(DESTDIR)$(PRIVATE_BINDIR)


.PHONY: clean
clean:
	$(RM) *.o $(PROGRAMS)
	$(RM) $(DEPS)

-include $(DEPS)
