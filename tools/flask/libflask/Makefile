MAJOR    = 1.0
MINOR    = 0

XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

XEN_LIBXC = $(XEN_ROOT)/tools/libxc

SRCS       :=
SRCS       += flask_op.c

CFLAGS   += -Werror
CFLAGS   += -fno-strict-aliasing
CFLAGS   += $(INCLUDES) -I./include -I$(XEN_LIBXC) -I$(XEN_INCLUDE)

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
LDFLAGS  += -L.

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS))

LIB := libflask.a
LIB += libflask.so libflask.so.$(MAJOR) libflask.so.$(MAJOR).$(MINOR)

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) $(LIB)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_DIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_PROG) libflask.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_DATA) libflask.a $(DESTDIR)$(LIBDIR)
	ln -sf libflask.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libflask.so.$(MAJOR)
	ln -sf libflask.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libflask.so
	$(INSTALL_DATA) include/libflask.h $(DESTDIR)$(INCLUDEDIR)/xen/xsm

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.a *.so* *.o *.opic *.rpm $(LIB) *~ $(DEPS) xen

# libflask

libflask.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libflask.so: libflask.so.$(MAJOR)
	ln -sf $< $@
libflask.so.$(MAJOR): libflask.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libflask.so.$(MAJOR).$(MINOR): $(PIC_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libflask.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^

-include $(DEPS)
