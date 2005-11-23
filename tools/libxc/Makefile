
INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DATA	= $(INSTALL) -m0644
INSTALL_DIR	= $(INSTALL) -d -m0755

MAJOR    = 3.0
MINOR    = 0

CC       = gcc

XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SRCS       :=
SRCS       += xc_bvtsched.c
SRCS       += xc_core.c
SRCS       += xc_domain.c
SRCS       += xc_evtchn.c
SRCS       += xc_gnttab.c
SRCS       += xc_misc.c
SRCS       += xc_physdev.c
SRCS       += xc_private.c
SRCS       += xc_sedf.c
SRCS       += xc_tbuf.c

ifeq ($(XEN_TARGET_ARCH),x86_32)
SRCS       += xc_ptrace.c
SRCS       += xc_ptrace_core.c
endif

BUILD_SRCS :=
BUILD_SRCS += xc_linux_build.c
BUILD_SRCS += xc_load_bin.c
BUILD_SRCS += xc_load_elf.c
BUILD_SRCS += xg_private.c

ifeq ($(XEN_TARGET_ARCH),ia64)
BUILD_SRCS += xc_ia64_stubs.c
else
BUILD_SRCS += xc_load_aout9.c
BUILD_SRCS += xc_linux_restore.c
BUILD_SRCS += xc_linux_save.c
BUILD_SRCS += xc_vmx_build.c
endif

CFLAGS   += -Wall
CFLAGS   += -Werror
CFLAGS   += -O3
CFLAGS   += -fno-strict-aliasing
CFLAGS   += $(INCLUDES) -I.

# Define this to make it possible to run valgrind on code linked with these
# libraries.
CFLAGS   += -DVALGRIND # -O0 -ggdb3

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
LDFLAGS  += -L.
DEPS     = .*.d

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS))

LIB_BUILD_OBJS := $(patsubst %.c,%.o,$(BUILD_SRCS))
PIC_BUILD_OBJS := $(patsubst %.c,%.opic,$(BUILD_SRCS))

LIB := libxenctrl.a
LIB += libxenctrl.so libxenctrl.so.$(MAJOR) libxenctrl.so.$(MAJOR).$(MINOR)

LIB += libxenguest.a
LIB += libxenguest.so libxenguest.so.$(MAJOR) libxenguest.so.$(MAJOR).$(MINOR)

all: build
build: check-for-zlib mk-symlinks
	$(MAKE) $(LIB)

check-for-zlib:
	@if [ ! -e /usr/include/zlib.h ]; then \
	echo "***********************************************************"; \
	echo "ERROR: install zlib header files (http://www.gzip.org/zlib)"; \
	echo "***********************************************************"; \
	false; \
	fi

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

install: build
	[ -d $(DESTDIR)/usr/$(LIBDIR) ] || $(INSTALL_DIR) $(DESTDIR)/usr/$(LIBDIR)
	[ -d $(DESTDIR)/usr/include ] || $(INSTALL_DIR) $(DESTDIR)/usr/include
	$(INSTALL_PROG) libxenctrl.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DATA) libxenctrl.a $(DESTDIR)/usr/$(LIBDIR)
	ln -sf libxenctrl.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)/libxenctrl.so.$(MAJOR)
	ln -sf libxenctrl.so.$(MAJOR) $(DESTDIR)/usr/$(LIBDIR)/libxenctrl.so
	$(INSTALL_DATA) xenctrl.h $(DESTDIR)/usr/include

	$(INSTALL_PROG) libxenguest.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DATA) libxenguest.a $(DESTDIR)/usr/$(LIBDIR)
	ln -sf libxenguest.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)/libxenguest.so.$(MAJOR)
	ln -sf libxenguest.so.$(MAJOR) $(DESTDIR)/usr/$(LIBDIR)/libxenguest.so
	$(INSTALL_DATA) xenguest.h $(DESTDIR)/usr/include

.PHONY: TAGS clean rpm install all

TAGS:
	etags -t *.c *.h

clean:
	rm -rf *.a *.so* *.o *.opic *.rpm $(LIB) *~ $(DEPS) xen

rpm: build
	rm -rf staging
	mkdir staging
	mkdir staging/i386
	rpmbuild --define "staging$$PWD/staging" --define '_builddir.' \
		--define "_rpmdir$$PWD/staging" -bb rpm.spec
	mv staging/i386/*.rpm .
	rm -rf staging

# libxenctrl

libxenctrl.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxenctrl.so: libxenctrl.so.$(MAJOR)
	ln -sf $< $@
libxenctrl.so.$(MAJOR): libxenctrl.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenctrl.so.$(MAJOR).$(MINOR): $(PIC_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname -Wl,libxenctrl.so.$(MAJOR) -shared -o $@ $^

# libxenguest

libxenguest.a: $(LIB_BUILD_OBJS)
	$(AR) rc $@ $^

libxenguest.so: libxenguest.so.$(MAJOR)
	ln -sf $< $@
libxenguest.so.$(MAJOR): libxenguest.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenguest.so.$(MAJOR).$(MINOR): $(PIC_BUILD_OBJS) libxenctrl.so
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname -Wl,libxenguest.so.$(MAJOR) -shared -o $@ $^ -lz -lxenctrl

-include $(DEPS)
