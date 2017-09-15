XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 0
SHLIB_LDFLAGS += -Wl,--version-script=libxencall.map

CFLAGS   += -Werror -Wmissing-prototypes
CFLAGS   += -I./include $(CFLAGS_xeninclude)
CFLAGS   += $(CFLAGS_libxentoollog) $(CFLAGS_libxentoolcore)

SRCS-y                 += core.c buffer.c
SRCS-$(CONFIG_Linux)   += linux.c
SRCS-$(CONFIG_FreeBSD) += freebsd.c
SRCS-$(CONFIG_SunOS)   += solaris.c
SRCS-$(CONFIG_NetBSD)  += netbsd.c
SRCS-$(CONFIG_MiniOS)  += minios.c

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS-y))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS-y))

LIB := libxencall.a
ifneq ($(nosharedlibs),y)
LIB += libxencall.so
endif

PKG_CONFIG := xencall.pc
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(foreach pc,$(PKG_CONFIG),$(PKG_CONFIG_DIR)/$(pc))

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_LIBXENCALL)/include
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_CFLAGS_LOCAL = $(CFLAGS_xeninclude)

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) libs

.PHONY: libs
libs: headers.chk $(LIB) $(PKG_CONFIG_INST) $(PKG_CONFIG_LOCAL)

headers.chk: $(wildcard include/*.h)

libxencall.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxencall.so: libxencall.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxencall.so.$(MAJOR): libxencall.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxencall.so.$(MAJOR).$(MINOR): $(PIC_OBJS) libxencall.map
	$(CC) $(LDFLAGS) $(PTHREAD_LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxencall.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(LDLIBS_libxentoollog) $(LDLIBS_libxentoolcore) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxencall.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxencall.a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxencall.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxencall.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxencall.so.$(MAJOR) $(DESTDIR)$(libdir)/libxencall.so
	$(INSTALL_DATA) include/xencall.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) xencall.pc $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/xencall.pc
	rm -f $(DESTDIR)$(includedir)/xencall.h
	rm -f $(DESTDIR)$(libdir)/libxencall.so
	rm -f $(DESTDIR)$(libdir)/libxencall.so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/libxencall.so.$(MAJOR).$(MINOR)
	rm -f $(DESTDIR)$(libdir)/libxencall.a

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS_RM) $(LIB_OBJS) $(PIC_OBJS)
	rm -f libxencall.so.$(MAJOR).$(MINOR) libxencall.so.$(MAJOR)
	rm -f headers.chk
	rm -f xencall.pc

.PHONY: distclean
distclean: clean
