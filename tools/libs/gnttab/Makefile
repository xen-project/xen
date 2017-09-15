XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 1
SHLIB_LDFLAGS += -Wl,--version-script=libxengnttab.map

CFLAGS   += -Werror -Wmissing-prototypes
CFLAGS   += -I./include $(CFLAGS_xeninclude)
CFLAGS   += $(CFLAGS_libxentoollog) $(CFLAGS_libxentoolcore)

SRCS-GNTTAB            += gnttab_core.c
SRCS-GNTSHR            += gntshr_core.c

SRCS-$(CONFIG_Linux)   += $(SRCS-GNTTAB) $(SRCS-GNTSHR) linux.c
SRCS-$(CONFIG_MiniOS)  += $(SRCS-GNTTAB) gntshr_unimp.c minios.c
SRCS-$(CONFIG_FreeBSD) += $(SRCS-GNTTAB) $(SRCS-GNTSHR) freebsd.c
SRCS-$(CONFIG_SunOS)   += gnttab_unimp.c gntshr_unimp.c
SRCS-$(CONFIG_NetBSD)  += gnttab_unimp.c gntshr_unimp.c

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS-y))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS-y))

LIB := libxengnttab.a
ifneq ($(nosharedlibs),y)
LIB += libxengnttab.so
endif

PKG_CONFIG := xengnttab.pc
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(foreach pc,$(PKG_CONFIG),$(PKG_CONFIG_DIR)/$(pc))

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_LIBXENGNTTAB)/include
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

libxengnttab.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxengnttab.so: libxengnttab.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxengnttab.so.$(MAJOR): libxengnttab.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxengnttab.so.$(MAJOR).$(MINOR): $(PIC_OBJS) libxengnttab.map
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxengnttab.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(LDLIBS_libxentoollog) $(LDLIBS_libxentoolcore) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxengnttab.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxengnttab.a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxengnttab.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxengnttab.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxengnttab.so.$(MAJOR) $(DESTDIR)$(libdir)/libxengnttab.so
	$(INSTALL_DATA) include/xengnttab.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) xengnttab.pc $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/xengnttab.pc
	rm -f $(DESTDIR)$(includedir)/xengnttab.h
	rm -f $(DESTDIR)$(libdir)/libxengnttab.so
	rm -f $(DESTDIR)$(libdir)/libxengnttab.so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/libxengnttab.so.$(MAJOR).$(MINOR)
	rm -f $(DESTDIR)$(libdir)/libxengnttab.a

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS_RM) $(LIB_OBJS) $(PIC_OBJS)
	rm -f libxengnttab.so.$(MAJOR).$(MINOR) libxengnttab.so.$(MAJOR)
	rm -f headers.chk
	rm -f xengnttab.pc

.PHONY: distclean
distclean: clean
