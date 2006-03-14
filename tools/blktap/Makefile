MAJOR    = 3.0
MINOR    = 0
SONAME   = libblktap.so.$(MAJOR)

XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS :=
SUBDIRS += ublkback
#SUBDIRS += parallax

BLKTAP_INSTALL_DIR = /usr/sbin

INSTALL            = install
INSTALL_PROG       = $(INSTALL) -m0755
INSTALL_DIR        = $(INSTALL) -d -m0755

INCLUDES += -I. -I $(XEN_LIBXC) -I $(XEN_XENSTORE)

LIBS     := -lpthread -lz

SRCS     :=
SRCS     += blktaplib.c xenbus.c blkif.c

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -fno-strict-aliasing
CFLAGS   += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
# get asprintf():
CFLAGS   += -D _GNU_SOURCE
# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
CFLAGS   += $(INCLUDES) 
DEPS     = .*.d

OBJS     = $(patsubst %.c,%.o,$(SRCS))
IBINS   :=
#IBINS   += blkdump

LIB      = libblktap.so libblktap.so.$(MAJOR) libblktap.so.$(MAJOR).$(MINOR)

all: mk-symlinks libblktap.so #blkdump
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@;       \
	done

install: all
	$(INSTALL_DIR) -p $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DIR) -p $(DESTDIR)/usr/include
	$(INSTALL_PROG) $(LIB) $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_PROG) blktaplib.h $(DESTDIR)/usr/include
	#$(INSTALL_PROG) $(IBINS) $(DESTDIR)$(BLKTAP_INSTALL_DIR)
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@;       \
	done

clean:
	rm -rf *.a *.so *.o *.rpm $(LIB) *~ $(DEPS) xen TAGS blkdump
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@;       \
	done

rpm: all
	rm -rf staging
	mkdir staging
	mkdir staging/i386
	rpmbuild --define "staging$$PWD/staging" --define '_builddir.' \
		--define "_rpmdir$$PWD/staging" -bb rpm.spec
	mv staging/i386/*.rpm .
	rm -rf staging

libblktap.so: $(OBJS) 
	$(CC) $(CFLAGS) -Wl,-soname -Wl,$(SONAME) -shared         \
	      -L$(XEN_XENSTORE) -l xenstore                       \
	      -o libblktap.so.$(MAJOR).$(MINOR) $^ $(LIBS)
	ln -sf libblktap.so.$(MAJOR).$(MINOR) libblktap.so.$(MAJOR)
	ln -sf libblktap.so.$(MAJOR) $@

blkdump: libblktap.so
	$(CC) $(CFLAGS) -o blkdump -L$(XEN_LIBXC) -L. \
	      -l blktap blkdump.c

.PHONY: TAGS clean install mk-symlinks rpm

TAGS:
	etags -t $(SRCS) *.h

-include $(DEPS)

