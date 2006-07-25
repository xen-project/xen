XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 3.0
MINOR    = 0
SONAME   = libblktap.so.$(MAJOR)

BLKTAP_INSTALL_DIR = /usr/sbin

INSTALL            = install
INSTALL_PROG       = $(INSTALL) -m0755
INSTALL_DIR        = $(INSTALL) -d -m0755

INCLUDES += -I. -I.. -I $(XEN_LIBXC) -I $(XEN_XENSTORE)

LIBS     := -lz

SRCS     :=
SRCS     += xenbus.c blkif.c xs_api.c

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -fno-strict-aliasing -fPIC
CFLAGS   += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
# get asprintf():
CFLAGS   += -D _GNU_SOURCE

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
CFLAGS   += $(INCLUDES) 
DEPS     = .*.d

OBJS     = $(patsubst %.c,%.o,$(SRCS))
IBINS   :=

LIB      = libblktap.a libblktap.so.$(MAJOR).$(MINOR)

all: build

build:
	$(MAKE) libblktap

install: all
	$(INSTALL_DIR) -p $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DIR) -p $(DESTDIR)/usr/include
	$(INSTALL_PROG) $(LIB) $(DESTDIR)/usr/$(LIBDIR)
	ln -sf libblktap.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)/libblktap.so.$(MAJOR)
	ln -sf libblktap.so.$(MAJOR) $(DESTDIR)/usr/$(LIBDIR)/libblktap.so
	$(INSTALL_PROG) blktaplib.h $(DESTDIR)/usr/include

clean:
	rm -rf *.a *.so* *.o *.rpm $(LIB) *~ $(DEPS) xen TAGS

libblktap: $(OBJS) 
	$(CC) $(CFLAGS) -Wl,-soname -Wl,$(SONAME) -shared         \
	      -L$(XEN_XENSTORE) -l xenstore                       \
	      -o libblktap.so.$(MAJOR).$(MINOR) $^ $(LIBS)
	ln -sf libblktap.so.$(MAJOR).$(MINOR) libblktap.so.$(MAJOR)
	ln -sf libblktap.so.$(MAJOR) $@.so
	ar rc libblktap.a $@.so

.PHONY: TAGS all build clean install libblktap

TAGS:
	etags -t $(SRCS) *.h

-include $(DEPS)

