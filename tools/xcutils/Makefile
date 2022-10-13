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

TARGETS := readnotes lsevtchn

CFLAGS_readnotes.o  := $(CFLAGS_libxenevtchn) $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest)
CFLAGS_lsevtchn.o   := $(CFLAGS_libxenevtchn) $(CFLAGS_libxenctrl)

.PHONY: all
all: $(TARGETS)

readnotes: readnotes.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(APPEND_LDFLAGS)

lsevtchn: lsevtchn.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) $(TARGETS) $(DESTDIR)$(LIBEXEC_BIN)

.PHONY: uninstall
uninstall:
	$(RM) $(addprefix $(DESTDIR)$(LIBEXECDIR)/, $(TARGETS))

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) $(DEPS_RM)

.PHONY: distclean
distclean: clean

-include $(DEPS_INCLUDE)
