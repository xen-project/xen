INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DATA	= $(INSTALL) -m0644
INSTALL_DIR	= $(INSTALL) -d -m0755

MAJOR    = 2.0
MINOR    = 0
SONAME   = libxc.so.$(MAJOR)

CC       = gcc

XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

vpath %c       $(XEN_LIBXUTIL)
INCLUDES += -I $(XEN_LIBXUTIL)

SRCS     :=
SRCS     += xc_atropos.c
SRCS     += xc_bvtsched.c
SRCS     += xc_domain.c
SRCS     += xc_evtchn.c
SRCS     += xc_io.c
SRCS     += xc_linux_build.c
SRCS     += xc_plan9_build.c
SRCS     += xc_linux_restore.c
SRCS     += xc_linux_save.c
SRCS     += xc_misc.c
SRCS     += xc_physdev.c
SRCS     += xc_private.c
SRCS     += xc_rrobin.c

CFLAGS   += -Wall
CFLAGS   += -Werror
CFLAGS   += -O3
CFLAGS   += -fno-strict-aliasing
CFLAGS   += $(INCLUDES) -I.
# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

OBJS     = $(patsubst %.c,%.o,$(SRCS))

LIB      = libxc.so libxc.so.$(MAJOR) libxc.so.$(MAJOR).$(MINOR)

all: check-for-zlib mk-symlinks
	$(MAKE) $(LIB)

check-for-zlib:
	@if [ ! -e /usr/include/zlib.h ]; then \
	echo "***********************************************************"; \
	echo "ERROR: install zlib header files (http://www.gzip.org/zlib)"; \
	echo "***********************************************************"; \
	false; \
	fi

LINUX_ROOT := $(wildcard $(XEN_ROOT)/linux-2.6.*-xen-sparse)
mk-symlinks:
	[ -e xen/linux ] || mkdir -p xen/linux
	[ -e xen/io ]    || mkdir -p xen/io
	( cd xen >/dev/null ; \
	  ln -sf ../$(XEN_ROOT)/xen/include/public/*.h . )
	( cd xen/io >/dev/null ; \
	   ln -sf ../../$(XEN_ROOT)/xen/include/public/io/*.h . )
	( cd xen/linux >/dev/null ; \
	  ln -sf ../../$(LINUX_ROOT)/include/asm-xen/linux-public/*.h . )

install: all
	[ -d $(DESTDIR)/usr/lib ] || $(INSTALL_DIR) $(DESTDIR)/usr/lib
	[ -d $(DESTDIR)/usr/include ] || $(INSTALL_DIR) $(DESTDIR)/usr/include
	$(INSTALL_PROG) libxc.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/lib
	ln -sf libxc.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/lib/libxc.so.$(MAJOR)
	ln -sf libxc.so.$(MAJOR) $(DESTDIR)/usr/lib/libxc.so
	$(INSTALL_DATA) xc.h $(DESTDIR)/usr/include

clean:
	rm -rf *.a *.so *.o *.rpm $(LIB) *~ $(DEPS) xen

rpm: all
	rm -rf staging
	mkdir staging
	mkdir staging/i386
	rpmbuild --define "staging$$PWD/staging" --define '_builddir.' \
		--define "_rpmdir$$PWD/staging" -bb rpm.spec
	mv staging/i386/*.rpm .
	rm -rf staging

libxc.so:
	ln -sf libxc.so.$(MAJOR) $@
libxc.so.$(MAJOR):
	ln -sf libxc.so.$(MAJOR).$(MINOR) $@
libxc.so.$(MAJOR).$(MINOR): $(OBJS)
	$(CC) -Wl,-soname -Wl,$(SONAME) -shared -o $@ $^ -L../libxutil -lxutil -lz

-include $(DEPS)
