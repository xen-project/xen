XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SRCS     = secpol_tool.c
CFLAGS   += -static
CFLAGS   += -Wall
CFLAGS   += -Werror
CFLAGS   += -O3
CFLAGS   += -fno-strict-aliasing
CFLAGS   += -I.

all: build
build: mk-symlinks
	$(MAKE) secpol_tool

default: all

install: all

secpol_tool : secpol_tool.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

clean:
	rm -rf secpol_tool xen


LINUX_ROOT := $(XEN_ROOT)/linux-2.6-xen-sparse
mk-symlinks:
	[ -e xen/linux ] || mkdir -p xen/linux
	[ -e xen/io ]    || mkdir -p xen/io
	( cd xen >/dev/null ; \
	  ln -sf ../$(XEN_ROOT)/xen/include/public/*.h . )
	( cd xen/io >/dev/null ; \
	  ln -sf ../../$(XEN_ROOT)/xen/include/public/io/*.h . )
	( cd xen/linux >/dev/null ; \
	  ln -sf ../../$(LINUX_ROOT)/include/asm-xen/linux-public/*.h . )
