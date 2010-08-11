XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 3.0
MINOR    = 0
SONAME   = libblktap.so.$(MAJOR)

CFLAGS   += -I.
CFLAGS   += $(CFLAGS_libxenctrl)
CFLAGS   += $(CFLAGS_libxenstore)
LDLIBS   += $(LDLIBS_libxenstore)

SRCS     :=
SRCS     += xenbus.c blkif.c xs_api.c

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -fPIC
# get asprintf():
CFLAGS   += -D _GNU_SOURCE

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

OBJS     = $(SRCS:.c=.o)
OBJS_PIC = $(SRCS:.c=.opic)
IBINS   :=

LIB      = libblktap.a libblktap.so.$(MAJOR).$(MINOR)

.PHONY: all
all: $(LIB)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_DIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) $(LIB) $(DESTDIR)$(LIBDIR)
	ln -sf libblktap.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libblktap.so.$(MAJOR)
	ln -sf libblktap.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libblktap.so
	$(INSTALL_DATA) blktaplib.h $(DESTDIR)$(INCLUDEDIR)

.PHONY: clean
clean:
	rm -rf *.a *.so* *.o *.opic *.rpm $(LIB) *~ $(DEPS) xen TAGS

libblktap.so.$(MAJOR).$(MINOR): $(OBJS_PIC) 
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,$(SONAME) $(SHLIB_LDFLAGS) \
	      -o $@ $^ $(LDLIBS)
	ln -sf libblktap.so.$(MAJOR).$(MINOR) libblktap.so.$(MAJOR)
	ln -sf libblktap.so.$(MAJOR) libblktap.so

libblktap.a: $(OBJS) 
	$(AR) rc $@ $^

.PHONY: TAGS
TAGS:
	etags -t $(SRCS) *.h

-include $(DEPS)

