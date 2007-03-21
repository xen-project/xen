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

PROGRAMS_INSTALL_DIR = /usr/$(LIBDIR)/xen/bin

INCLUDES += -I $(XEN_LIBXC) -I $(XEN_XENSTORE)

CFLAGS += -Werror -fno-strict-aliasing
CFLAGS += $(INCLUDES)

# Make gcc generate dependencies.
CFLAGS += -Wp,-MD,.$(@F).d
PROG_DEP = .*.d

PROGRAMS = xc_restore xc_save readnotes

LDLIBS   = -L$(XEN_LIBXC) -L$(XEN_XENSTORE) -lxenguest -lxenctrl -lxenstore

.PHONY: all
all: build

.PHONY: build
build: $(PROGRAMS)

$(PROGRAMS): %: %.o
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

.PHONY: install
install: build
	[ -d $(DESTDIR)$(PROGRAMS_INSTALL_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(PROGRAMS_INSTALL_DIR)
	$(INSTALL_PROG) $(PROGRAMS) $(DESTDIR)$(PROGRAMS_INSTALL_DIR)


.PHONY: clean
clean:
	$(RM) *.o $(PROGRAMS)
	$(RM) $(PROG_DEP)

-include $(PROG_DEP)
