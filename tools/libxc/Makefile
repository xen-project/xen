
MAJOR    = 1.3
MINOR    = 0
SONAME   = libxc.so.$(MAJOR)

CC       = gcc

XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Make.defs

vpath %h       $(XEN_LINUX_INCLUDE)
INCLUDES += -I $(XEN_LINUX_INCLUDE)

vpath %c       $(XEN_LIBXUTIL)
INCLUDES += -I $(XEN_LIBXUTIL)

SRCS     :=
SRCS     += xc_atropos.c
SRCS     += xc_bvtsched.c
SRCS     += xc_domain.c
SRCS     += xc_evtchn.c
SRCS     += xc_io.c
SRCS     += xc_linux_build.c
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
CFLAGS   += $(INCLUDES)
# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

OBJS     = $(patsubst %.c,%.o,$(SRCS))

LIB      = libxc.so libxc.so.$(MAJOR) libxc.so.$(MAJOR).$(MINOR)

all: check-for-zlib mk-symlinks $(LIB)

check-for-zlib:
	@if [ ! -e /usr/include/zlib.h ]; then \
	echo "***********************************************************"; \
	echo "ERROR: install zlib header files (http://www.gzip.org/zlib)"; \
	echo "***********************************************************"; \
	false; \
	fi

mk-symlinks:
	[ -e xen ] || ln -sf $(XEN_HYPERVISOR_IFS) xen

install: all
	mkdir -p $(prefix)/usr/lib
	mkdir -p $(prefix)/usr/include
	install -m0755 $(LIB) $(prefix)/usr/lib
	ln -sf libxc.so.$(MAJOR).$(MINOR) $(prefix)/usr/lib/libxc.so.$(MAJOR)
	ln -sf libxc.so.$(MAJOR) $(prefix)/usr/lib/libxc.so
	install -m0644 xc.h $(prefix)/usr/include

clean:
	$(RM) *.a *.so *.o *.rpm $(LIB) *~ $(DEPS) xen

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
