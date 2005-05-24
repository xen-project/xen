#
# tools/xcutils/Makefile
#
# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.
#
# Copyright (C) 2005 by Christian Limpach
#

INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

XEN_ROOT	= ../..
include $(XEN_ROOT)/tools/Rules.mk

PROGRAMS_INSTALL_DIR	= /usr/libexec/xen

INCLUDES += -I $(XEN_LIBXC)

CC := gcc

CFLAGS += -Wall -Werror -O3 -fno-strict-aliasing
CFLAGS += $(INCLUDES)

# Make gcc generate dependencies.
CFLAGS += -Wp,-MD,.$(@F).d
PROG_DEP = .*.d

PROGRAMS		= xc_restore

LDLIBS			= -L$(XEN_LIBXC) -lxc -L$(XEN_LIBXUTIL) -lxutil

.PHONY: all
all: build
build: $(PROGRAMS)

$(PROGRAMS): %: %.o
	$(LINK.o) $^ $(LDLIBS) -o $@

.PHONY: install
install: build
	[ -d $(DESTDIR)$(PROGRAMS_INSTALL_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(PROGRAMS_INSTALL_DIR)
	$(INSTALL_PROG) $(PROGRAMS) $(DESTDIR)$(PROGRAMS_INSTALL_DIR)


clean:
	$(RM) *.o $(PROGRAMS)
	$(RM) $(PROG_DEP)

-include $(PROG_DEP)
