XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 3.0
MINOR    = 0
SONAME   = libblktap.so.$(MAJOR)

INCLUDES += -I. -I.. -I $(XEN_LIBXC) -I$(XEN_INCLUDE) $(CFLAGS_libxenstore)

LDFLAGS  += $(LDFLAGS_libxenstore)

SRCS     :=
SRCS     += xenbus.c blkif.c xs_api.c

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -fPIC
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
	$(INSTALL_DIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_DIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) $(LIB) $(DESTDIR)$(LIBDIR)
	ln -sf libblktap.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libblktap.so.$(MAJOR)
	ln -sf libblktap.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libblktap.so
	$(INSTALL_DATA) blktaplib.h $(DESTDIR)$(INCLUDEDIR)

clean:
	rm -rf *.a *.so* *.o *.rpm $(LIB) *~ $(DEPS) xen TAGS

libblktap.a: $(OBJS) 
	$(CC) $(CFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,$(SONAME) $(SHLIB_CFLAGS) \
	      -L$(XEN_XENSTORE) $(LDFLAGS)                                 \
	      -o libblktap.so.$(MAJOR).$(MINOR) $^ $(LIBS)
	ln -sf libblktap.so.$(MAJOR).$(MINOR) libblktap.so.$(MAJOR)
	ln -sf libblktap.so.$(MAJOR) libblktap.so
	$(AR) rc $@ libblktap.so

.PHONY: TAGS all build clean install libblktap

TAGS:
	etags -t $(SRCS) *.h

-include $(DEPS)

