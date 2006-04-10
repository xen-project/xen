
INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DATA	= $(INSTALL) -m0644
INSTALL_DIR	= $(INSTALL) -d -m0755

MAJOR    = 3.0
MINOR    = 0

XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

SRCS     := xendebug.c

CFLAGS   += -Werror -fno-strict-aliasing
CFLAGS   += $(INCLUDES) -I. -I$(XEN_ROOT)/tools/libxc
# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

LDFLAGS  += -L$(XEN_ROOT)/tools/libxc -lxenctrl

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS))

LIB      := libxendebug.a libxendebug.so
LIB      += libxendebug.so.$(MAJOR) libxendebug.so.$(MAJOR).$(MINOR)

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) $(LIB)

.PHONY: install
install: build
	[ -d $(DESTDIR)/usr/$(LIBDIR) ] || $(INSTALL_DIR) $(DESTDIR)/usr/$(LIBDIR)
	[ -d $(DESTDIR)/usr/include ] || $(INSTALL_DIR) $(DESTDIR)/usr/include
	$(INSTALL_PROG) libxendebug.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DATA) libxendebug.a $(DESTDIR)/usr/$(LIBDIR)
	ln -sf libxendebug.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)/libxendebug.so.$(MAJOR)
	ln -sf libxendebug.so.$(MAJOR) $(DESTDIR)/usr/$(LIBDIR)/libxendebug.so
	$(INSTALL_DATA) xendebug.h $(DESTDIR)/usr/include

.PHONY: TAGS
TAGS:
	etags -t $(SRCS) *.h

.PHONY: clean
clean:
	rm -rf *.a *.so* *.o *.opic *.rpm $(LIB) *~ $(DEPS) xen

.PHONY: rpm
rpm: build
	rm -rf staging
	mkdir staging
	mkdir staging/i386
	rpmbuild --define "staging$$PWD/staging" --define '_builddir.' \
		--define "_rpmdir$$PWD/staging" -bb rpm.spec
	mv staging/i386/*.rpm .
	rm -rf staging

libxendebug.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxendebug.so: libxendebug.so.$(MAJOR)
	ln -sf $< $@
libxendebug.so.$(MAJOR): libxendebug.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxendebug.so.$(MAJOR).$(MINOR): $(PIC_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname -Wl,libxendebug.so.$(MAJOR) -shared -o $@ $^

-include $(DEPS)
