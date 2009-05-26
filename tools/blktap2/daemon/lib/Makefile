XEN_ROOT=../../../../
BLKTAP_ROOT := ../../
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 3.1
MINOR    = 0
SONAME   = libblktap.so.$(MAJOR)

BLKTAP_INSTALL_DIR = /usr/sbin

LIBS     := -lxenstore

ifneq ($(USE_SYSTEM_LIBRARIES),y)
INCLUDES += -I $(XEN_LIBXC) -I $(XEN_XENSTORE)
LIBS     += -L$(XEN_XENSTORE)
endif

SRCS     :=
SRCS     += xs_api.c
CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -fno-strict-aliasing -fPIC
# get asprintf():
CFLAGS   += -D _GNU_SOURCE
CFLAGS   += -g
CFLAGS   += -I../../include -I../../../include/ $(INCLUDES) 


# Get gcc to generate the dependencies for us.
CFLAGS  += -Wp,-MD,.$(@F).d
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
	$(INSTALL_DIR) -p $(DESTDIR)$(LIBDIR)
	$(INSTALL_DATA) $(LIB) $(DESTDIR)$(LIBDIR)
	ln -sf libblktap.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libblktap.so.$(MAJOR)
	ln -sf libblktap.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libblktap.so

clean:
	rm -rf *.a *.so* *.o *.rpm $(LIB) *~ $(DEPS) xen TAGS

libblktap.a: $(OBJS) 
	$(CC) $(CFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,$(SONAME) $(SHLIB_CFLAGS) \
	      -o libblktap.so.$(MAJOR).$(MINOR) $^ $(LIBS)
	ln -sf libblktap.so.$(MAJOR).$(MINOR) libblktap.so.$(MAJOR)
	ln -sf libblktap.so.$(MAJOR) libblktap.so
	$(AR) rc $@ libblktap.so

.PHONY: TAGS all build clean install libblktap

TAGS:
	etags -t $(SRCS) *.h

-include $(DEPS)

