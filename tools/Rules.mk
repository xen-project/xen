#  -*- mode: Makefile; -*-

XEN_XC             = $(XEN_ROOT)/tools/python/xen/lowlevel/xc
XEN_LIBXC          = $(XEN_ROOT)/tools/libxc
XEN_LIBXUTIL       = $(XEN_ROOT)/tools/libxutil

XEN_COMPILE_ARCH  ?= $(shell uname -m | sed -e s/i.86/x86_32/)
XEN_TARGET_ARCH   ?= $(XEN_COMPILE_ARCH)

ifeq ($(XEN_TARGET_ARCH),x86_32)
CFLAGS  += -m32 -march=i686
LDFLAGS += -m elf_i386
endif

ifeq ($(XEN_TARGET_ARCH),x86_64)
CFLAGS  += -m64
LDFLAGS += -m elf_x86_64
endif

%.opic: %.c
	$(CC) $(CPPFLAGS) -DPIC $(CFLAGS) -fPIC -c -o $@ $<

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<
