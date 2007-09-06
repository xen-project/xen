#
# xen/arch/ia64/tools/p2m_foreign
#
# Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
#                    VA Linux Systems Japan K.K.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

XEN_ROOT	= ../../../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror -ggdb3
CFLAGS += -I$(XEN_LIBXC) -I$(XEN_XENSTORE)

# Make gcc generate dependencies.
CFLAGS += -Wp,-MD,.$(@F).d
DEPS = .*.d

PROGRAMS = p2m_foreign
LDLIBS   = -L$(XEN_LIBXC) -L$(XEN_XENSTORE) -lxenguest -lxenctrl

.PHONY: all
all: build

.PHONY: build
build: $(PROGRAMS)

$(PROGRAMS): %: %.o
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@


.PHONY: install
install:

.PHONY: clean
clean:
	$(RM) *.o $(PROGRAMS)
	$(RM) $(DEPS)

-include $(DEPS)
