#
# Copyright (c) 2006-2007, XenSource Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
#
XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR = 1.0
MINOR = 0

CFLAGS += -Iinclude                     \
          $(shell xml2-config --cflags) \
          $(shell curl-config --cflags) \
          -fPIC

LDFLAGS += $(shell xml2-config --libs) \
           $(shell curl-config --libs)

LIBXENAPI_HDRS = $(wildcard include/xen/api/*.h) include/xen/api/xen_all.h
LIBXENAPI_OBJS = $(patsubst %.c, %.o, $(wildcard src/*.c))

TEST_PROGRAMS = test/test_bindings test/test_event_handling

.PHONY: all
all: libxenapi.so libxenapi.a

libxenapi.so: libxenapi.so.$(MAJOR)
	ln -sf $< $@

libxenapi.so.$(MAJOR): libxenapi.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenapi.so.$(MAJOR).$(MINOR): $(LIBXENAPI_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenapi.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^

libxenapi.a: $(LIBXENAPI_OBJS)
	$(AR) rcs libxenapi.a $^

$(TEST_PROGRAMS): test/%: test/%.o libxenapi.so
	$(CC) $(LDFLAGS) -o $@ $< -L . -lxenapi


.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(INCLUDEDIR)/xen/api
	$(INSTALL_DIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_PROG) libxenapi.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)
	ln -sf libxenapi.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libxenapi.so.$(MAJOR)
	ln -sf libxenapi.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libxenapi.so
	$(INSTALL_DATA) libxenapi.a $(DESTDIR)$(LIBDIR)
	set -e; for i in $(LIBXENAPI_HDRS); do \
	    $(INSTALL_DATA) $$i $(DESTDIR)$(INCLUDEDIR)/xen/api; \
	done


.PHONY: clean
clean:
	rm -f `find -name *.o`
	rm -f libxenapi.so*
	rm -f libxenapi.a
	rm -f $(TEST_PROGRAMS)
