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

# Enable implicit LFS support *and* explicit LFS names.
CFLAGS  += $(shell getconf LFS_CFLAGS)
CFLAGS  += -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
LDFLAGS += $(shell getconf LFS_LDFLAGS)

# 32-bit x86 does not perform well with -ve segment accesses on Xen.
CFLAGS-$(CONFIG_X86_32) += $(call cc-option,$(CC),-mno-tls-direct-seg-refs)
CFLAGS += $(CFLAGS-y)

# Require GCC v3.4+ (to avoid issues with alignment constraints in Xen headers)
check-$(CONFIG_X86) = $(call cc-ver-check,CC,0x030400,\
                        "Xen requires at least gcc-3.4")
$(eval $(check-y))

%.opic: %.c
	$(CC) $(CPPFLAGS) -DPIC $(CFLAGS) -fPIC -c -o $@ $<

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

%.o: %.cc
	$(CC) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<

.PHONY: mk-symlinks mk-symlinks-xen mk-symlinks-$(XEN_OS)

mk-symlinks-SunOS:

mk-symlinks-Linux: LINUX_ROOT=$(XEN_ROOT)/linux-2.6-xen-sparse
mk-symlinks-Linux:
	mkdir -p xen/linux
	( cd xen/linux && \
	  ln -sf ../../$(LINUX_ROOT)/include/xen/public/*.h . )
	( cd xen && rm -f sys && ln -sf linux sys )

mk-symlinks-xen:
	mkdir -p xen
	( cd xen && ln -sf ../$(XEN_ROOT)/xen/include/public/*.h . )
	mkdir -p xen/hvm
	( cd xen/hvm && ln -sf ../../$(XEN_ROOT)/xen/include/public/hvm/*.h . )
	mkdir -p xen/io
	( cd xen/io && ln -sf ../../$(XEN_ROOT)/xen/include/public/io/*.h . )
	mkdir -p xen/arch-x86
	( cd xen/arch-x86 && ln -sf ../../$(XEN_ROOT)/xen/include/public/arch-x86/*.h . )
	mkdir -p xen/foreign
	( cd xen/foreign && ln -sf ../../$(XEN_ROOT)/xen/include/public/foreign/Makefile . )
	( cd xen/foreign && ln -sf ../../$(XEN_ROOT)/xen/include/public/foreign/reference.size . )
	( cd xen/foreign && ln -sf ../../$(XEN_ROOT)/xen/include/public/foreign/*.py . )
	$(MAKE) -C xen/foreign

mk-symlinks: mk-symlinks-xen mk-symlinks-$(XEN_OS)
