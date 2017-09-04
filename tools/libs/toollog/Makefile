XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR	= 1
MINOR	= 0
SHLIB_LDFLAGS += -Wl,--version-script=libxentoollog.map

CFLAGS	+= -Werror -Wmissing-prototypes
CFLAGS	+= -I./include

SRCS-y	+= xtl_core.c
SRCS-y	+= xtl_logger_stdio.c

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS-y))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS-y))

LIB := libxentoollog.a
ifneq ($(nosharedlibs),y)
LIB += libxentoollog.so
endif

PKG_CONFIG := xentoollog.pc
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(foreach pc,$(PKG_CONFIG),$(PKG_CONFIG_DIR)/$(pc))

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_LIBXENTOOLLOG)/include
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) libs

.PHONY: libs
libs: headers.chk $(LIB) $(PKG_CONFIG_INST) $(PKG_CONFIG_LOCAL)

headers.chk: $(wildcard include/*.h)

libxentoollog.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxentoollog.so: libxentoollog.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxentoollog.so.$(MAJOR): libxentoollog.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxentoollog.so.$(MAJOR).$(MINOR): $(PIC_OBJS) libxentoollog.map
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxentoollog.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxentoollog.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxentoollog.a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxentoollog.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxentoollog.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxentoollog.so.$(MAJOR) $(DESTDIR)$(libdir)/libxentoollog.so
	$(INSTALL_DATA) include/xentoollog.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) xentoollog.pc $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uinstall
uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/xentoollog.pc
	rm -f $(DESTDIR)$(includedir)/xentoollog.h
	rm -f $(DESTDIR)$(libdir)/libxentoollog.so
	rm -f $(DESTDIR)$(libdir)/libxentoollog.so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/libxentoollog.so.$(MAJOR).$(MINOR)
	rm -f $(DESTDIR)$(libdir)/libxentoollog.a

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS_RM) $(LIB_OBJS) $(PIC_OBJS)
	rm -f libxentoollog.so.$(MAJOR).$(MINOR) libxentoollog.so.$(MAJOR)
	rm -f headers.chk
	rm -f xentoollog.pc

.PHONY: distclean
distclean: clean
