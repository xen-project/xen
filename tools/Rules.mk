#  -*- mode: Makefile; -*-

include $(XEN_ROOT)/Config.mk

XEN_XC             = $(XEN_ROOT)/tools/python/xen/lowlevel/xc
XEN_LIBXC          = $(XEN_ROOT)/tools/libxc
XEN_LIBXUTIL       = $(XEN_ROOT)/tools/libxutil

ifeq ($(XEN_TARGET_ARCH),x86_32)
CFLAGS  += -m32 -march=i686
LDFLAGS += -m elf_i386
X11_LDPATH = -L/usr/X11R6/lib
endif

ifeq ($(XEN_TARGET_ARCH),x86_64)
CFLAGS  += -m64
LDFLAGS += -m elf_x86_64
X11_LDPATH = -L/usr/X11R6/lib64
endif

%.opic: %.c
	$(CC) $(CPPFLAGS) -DPIC $(CFLAGS) -fPIC -c -o $@ $<

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

%.o: %.cc
	$(CC) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<
