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

INCLUDES += $(CFLAGS_libxenctrl) -I $(XEN_XENSTORE) -I$(XEN_INCLUDE)

CFLAGS += -Werror
CFLAGS += $(INCLUDES)

# Make gcc generate dependencies.
CFLAGS += -Wp,-MD,.$(@F).d
PROG_DEP = .*.d

PROGRAMS = xc_restore xc_save readnotes

LDLIBS   = $(LDFLAGS_libxenctrl) -L$(XEN_XENSTORE) -lxenguest -lxenstore

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
	$(RM) $(PROG_DEP)

-include $(PROG_DEP)
