XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 1
SHLIB_LDFLAGS += -Wl,--version-script=libxenevtchn.map

CFLAGS   += -Werror -Wmissing-prototypes
CFLAGS   += -I./include $(CFLAGS_xeninclude)
CFLAGS   += $(CFLAGS_libxentoollog) $(CFLAGS_libxentoolcore)

SRCS-y                 += core.c
SRCS-$(CONFIG_Linux)   += linux.c
SRCS-$(CONFIG_FreeBSD) += freebsd.c
SRCS-$(CONFIG_SunOS)   += solaris.c
SRCS-$(CONFIG_NetBSD)  += netbsd.c
SRCS-$(CONFIG_MiniOS)  += minios.c

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS-y))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS-y))

LIB := libxenevtchn.a
ifneq ($(nosharedlibs),y)
LIB += libxenevtchn.so
endif

PKG_CONFIG := xenevtchn.pc
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(foreach pc,$(PKG_CONFIG),$(PKG_CONFIG_DIR)/$(pc))

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_LIBXENEVTCHN)/include
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) libs

.PHONY: libs
libs: headers.chk $(LIB) $(PKG_CONFIG_INST) $(PKG_CONFIG_LOCAL)

headers.chk: $(wildcard include/*.h)

libxenevtchn.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxenevtchn.so: libxenevtchn.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxenevtchn.so.$(MAJOR): libxenevtchn.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxenevtchn.so.$(MAJOR).$(MINOR): $(PIC_OBJS) libxenevtchn.map
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenevtchn.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(LDLIBS_libxentoollog) $(LDLIBS_libxentoolcore) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxenevtchn.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxenevtchn.a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxenevtchn.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxenevtchn.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxenevtchn.so.$(MAJOR) $(DESTDIR)$(libdir)/libxenevtchn.so
	$(INSTALL_DATA) include/xenevtchn.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) xenevtchn.pc $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/xenevtchn.pc
	rm -f $(DESTDIR)$(includedir)/xenevtchn.h
	rm -f $(DESTDIR)$(libdir)/libxenevtchn.so
	rm -f $(DESTDIR)$(libdir)/libxenevtchn.so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/libxenevtchn.so.$(MAJOR).$(MINOR)
	rm -f $(DESTDIR)$(libdir)/libxenevtchn.a

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS_RM) $(LIB_OBJS) $(PIC_OBJS)
	rm -f libxenevtchn.so.$(MAJOR).$(MINOR) libxenevtchn.so.$(MAJOR)
	rm -f headers.chk
	rm -f xenevtchn.pc

.PHONY: distclean
distclean: clean
