XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 3.0
MINOR    = 0
SONAME   = libblktap.so.$(MAJOR)

BLKTAP_INSTALL_DIR = /usr/sbin

INCLUDES += -I. -I.. -I $(XEN_LIBXC) -I $(XEN_XENSTORE)

LIBS     := -lz

SRCS     :=
SRCS     += xenbus.c blkif.c xs_api.c

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -fno-strict-aliasing -fPIC
# get asprintf():
CFLAGS   += -D _GNU_SOURCE

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
CFLAGS   += $(INCLUDES) 
DEPS     = .*.d

OBJS     = $(patsubst %.c,%.o,$(SRCS))
IBINS   :=

LIB      = libblktap.a libblktap.so.$(MAJOR).$(MINOR)

.PHONY: all
all: build

.PHONY: build
build: libblktap.a

.PHONY: libblktap
libblktap: libblktap.a

install: all
	$(INSTALL_DIR) $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DIR) $(DESTDIR)/usr/include
	$(INSTALL_PROG) $(LIB) $(DESTDIR)/usr/$(LIBDIR)
	ln -sf libblktap.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)/libblktap.so.$(MAJOR)
	ln -sf libblktap.so.$(MAJOR) $(DESTDIR)/usr/$(LIBDIR)/libblktap.so
	$(INSTALL_PROG) blktaplib.h $(DESTDIR)/usr/include

clean:
	rm -rf *.a *.so* *.o *.rpm $(LIB) *~ $(DEPS) xen TAGS

libblktap.a: $(OBJS) 
	$(CC) $(CFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,$(SONAME) $(SHLIB_CFLAGS) \
	      -L$(XEN_XENSTORE) -l xenstore                                \
	      -o libblktap.so.$(MAJOR).$(MINOR) $^ $(LIBS)
	ln -sf libblktap.so.$(MAJOR).$(MINOR) libblktap.so.$(MAJOR)
	ln -sf libblktap.so.$(MAJOR) libblktap.so
	$(AR) rc $@ libblktap.so

.PHONY: TAGS all build clean install libblktap

TAGS:
	etags -t $(SRCS) *.h

-include $(DEPS)

