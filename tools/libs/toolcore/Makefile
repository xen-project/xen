XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR	= 1
MINOR	= 0
SHLIB_LDFLAGS += -Wl,--version-script=libxentoolcore.map

CFLAGS	+= -Werror -Wmissing-prototypes
CFLAGS	+= -I./include
CFLAGS	+= $(CFLAGS_xeninclude)

SRCS-y	+= handlereg.c

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS-y))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS-y))

LIB := libxentoolcore.a
ifneq ($(nosharedlibs),y)
LIB += libxentoolcore.so
endif

PKG_CONFIG := xentoolcore.pc
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(foreach pc,$(PKG_CONFIG),$(PKG_CONFIG_DIR)/$(pc))

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_LIBXENTOOLCORE)/include
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)

AUTOINCS=include/_xentoolcore_list.h

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) libs

.PHONY: libs
libs: headers.chk $(LIB) $(PKG_CONFIG_INST) $(PKG_CONFIG_LOCAL)

$(LIB_OBJS): $(AUTOINCS)
$(PIC_OBJS): $(AUTOINCS)

headers.chk: $(wildcard include/*.h) $(AUTOINCS)

include/_xentoolcore_list.h: $(XEN_INCLUDE)/xen-external/bsd-sys-queue-h-seddery $(XEN_INCLUDE)/xen-external/bsd-sys-queue.h
	$(PERL) $^ --prefix=xentoolcore >$@.new
	$(call move-if-changed,$@.new,$@)

libxentoolcore.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxentoolcore.so: libxentoolcore.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxentoolcore.so.$(MAJOR): libxentoolcore.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxentoolcore.so.$(MAJOR).$(MINOR): $(PIC_OBJS) libxentoolcore.map
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxentoolcore.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxentoolcore.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxentoolcore.a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxentoolcore.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxentoolcore.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxentoolcore.so.$(MAJOR) $(DESTDIR)$(libdir)/libxentoolcore.so
	$(INSTALL_DATA) include/xentoolcore.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) xentoolcore.pc $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uinstall
uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/xentoolcore.pc
	rm -f $(DESTDIR)$(includedir)/xentoolcore.h
	rm -f $(DESTDIR)$(libdir)/libxentoolcore.so
	rm -f $(DESTDIR)$(libdir)/libxentoolcore.so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/libxentoolcore.so.$(MAJOR).$(MINOR)
	rm -f $(DESTDIR)$(libdir)/libxentoolcore.a

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS_RM) $(LIB_OBJS) $(PIC_OBJS)
	rm -f libxentoolcore.so.$(MAJOR).$(MINOR) libxentoolcore.so.$(MAJOR)
	rm -f headers.chk
	rm -f xentoolcore.pc

.PHONY: distclean
distclean: clean
