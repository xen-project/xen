#  -*- mode: Makefile; -*-

# `all' is the default target
all:

include $(XEN_ROOT)/Config.mk

XEN_XC             = $(XEN_ROOT)/tools/python/xen/lowlevel/xc
XEN_LIBXC          = $(XEN_ROOT)/tools/libxc
XEN_XENSTORE       = $(XEN_ROOT)/tools/xenstore
XEN_LIBXENSTAT     = $(XEN_ROOT)/tools/xenstat/libxenstat/src

X11_LDPATH = -L/usr/X11R6/$(LIBDIR)

CFLAGS += -D__XEN_TOOLS__

%.opic: %.c
	$(CC) $(CPPFLAGS) -DPIC $(CFLAGS) -fPIC -c -o $@ $<

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

%.o: %.cc
	$(CC) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<

.PHONY: mk-symlinks
mk-symlinks: LINUX_ROOT=$(XEN_ROOT)/linux-2.6-xen-sparse
mk-symlinks:
	mkdir -p xen
	( cd xen && ln -sf ../$(XEN_ROOT)/xen/include/public/*.h . )
	mkdir -p xen/hvm
	( cd xen/hvm && ln -sf ../../$(XEN_ROOT)/xen/include/public/hvm/*.h . )
	mkdir -p xen/io
	( cd xen/io && ln -sf ../../$(XEN_ROOT)/xen/include/public/io/*.h . )
	mkdir -p xen/linux
	( cd xen/linux && \
	  ln -sf ../../$(LINUX_ROOT)/include/xen/public/*.h . )
