
INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DATA	= $(INSTALL) -m0644
INSTALL_DIR	= $(INSTALL) -d -m0755

MAJOR    = 3.0
MINOR    = 0

CC       = gcc

XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SRCS     :=
SRCS     += xc_sedf.c
SRCS     += xc_bvtsched.c
SRCS     += xc_core.c
SRCS     += xc_domain.c
SRCS     += xc_evtchn.c
SRCS     += xc_gnttab.c
SRCS     += xc_load_bin.c
SRCS     += xc_load_elf.c
SRCS     += xc_linux_build.c
SRCS     += xc_misc.c
SRCS     += xc_physdev.c
SRCS     += xc_private.c
ifeq ($(XEN_TARGET_ARCH),ia64)
SRCS     += xc_ia64_stubs.c
else
SRCS     += xc_load_aout9.c
SRCS     += xc_linux_restore.c
SRCS     += xc_linux_save.c
SRCS     += xc_vmx_build.c
SRCS     += xc_ptrace.c
SRCS     += xc_ptrace_core.c
endif

CFLAGS   += -Wall
CFLAGS   += -Werror
CFLAGS   += -O3
CFLAGS   += -fno-strict-aliasing
CFLAGS   += $(INCLUDES) -I.
# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS))

LIB      := libxc.a libxc-pic.a
LIB      += libxc.so libxc.so.$(MAJOR) libxc.so.$(MAJOR).$(MINOR)

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
	$(INSTALL_PROG) libxc.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DATA) libxc.a $(DESTDIR)/usr/$(LIBDIR)
	ln -sf libxc.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)/libxc.so.$(MAJOR)
	ln -sf libxc.so.$(MAJOR) $(DESTDIR)/usr/$(LIBDIR)/libxc.so
	$(INSTALL_DATA) xc.h $(DESTDIR)/usr/include

.PHONY: TAGS clean rpm install all

TAGS:
	etags -t $(SRCS) *.h

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

libxc.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxc-pic.a: $(PIC_OBJS)
	$(AR) rc $@ $^

libxc.so: libxc.so.$(MAJOR)
	ln -sf $< $@
libxc.so.$(MAJOR): libxc.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxc.so.$(MAJOR).$(MINOR): $(PIC_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname -Wl,libxc.so.$(MAJOR) -shared -o $@ $^ -lz

-include $(DEPS)
