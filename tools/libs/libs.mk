# Common Makefile for building a lib.
#
# Variables taken as input:
#   LIBNAME: name of lib to build, will be prepended with "libxen"
#   MAJOR:   major version of lib
#   MINOR:   minor version of lib
#   USELIBS: xen libs to use (e.g. "toolcore toollog")

SHLIB_LDFLAGS += -Wl,--version-script=libxen$(LIBNAME).map

CFLAGS   += -Werror -Wmissing-prototypes
CFLAGS   += -I./include $(CFLAGS_xeninclude)
CFLAGS   += $(foreach lib, $(USELIBS), $(CFLAGS_libxen$(lib)))

LDUSELIBS = $(foreach lib, $(USELIBS), $(LDLIBS_libxen$(lib)))

LIB_OBJS := $(SRCS-y:.c=.o)
PIC_OBJS := $(SRCS-y:.c=.opic)

LIB := libxen$(LIBNAME).a
ifneq ($(nosharedlibs),y)
LIB += libxen$(LIBNAME).so
endif

PKG_CONFIG := xen$(LIBNAME).pc
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(foreach pc,$(PKG_CONFIG),$(PKG_CONFIG_DIR)/$(pc))

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) libs

.PHONY: libs
libs: headers.chk $(LIB) $(PKG_CONFIG_INST) $(PKG_CONFIG_LOCAL)

headers.chk: $(wildcard include/*.h) $(AUTOINCS)

libxen$(LIBNAME).a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxen$(LIBNAME).so: libxen$(LIBNAME).so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxen$(LIBNAME).so.$(MAJOR): libxen$(LIBNAME).so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxen$(LIBNAME).so.$(MAJOR).$(MINOR): $(PIC_OBJS) libxen$(LIBNAME).map
	$(CC) $(LDFLAGS) $(PTHREAD_LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxen$(LIBNAME).so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(LDUSELIBS) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxen$(LIBNAME).so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxen$(LIBNAME).a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxen$(LIBNAME).so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxen$(LIBNAME).so.$(MAJOR)
	$(SYMLINK_SHLIB) libxen$(LIBNAME).so.$(MAJOR) $(DESTDIR)$(libdir)/libxen$(LIBNAME).so
	$(INSTALL_DATA) include/xen$(LIBNAME).h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) xen$(LIBNAME).pc $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/xen$(LIBNAME).pc
	rm -f $(DESTDIR)$(includedir)/xen$(LIBNAME).h
	rm -f $(DESTDIR)$(libdir)/libxen$(LIBNAME).so
	rm -f $(DESTDIR)$(libdir)/libxen$(LIBNAME).so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/libxen$(LIBNAME).so.$(MAJOR).$(MINOR)
	rm -f $(DESTDIR)$(libdir)/libxen$(LIBNAME).a

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS_RM) $(LIB_OBJS) $(PIC_OBJS)
	rm -f libxen$(LIBNAME).so.$(MAJOR).$(MINOR) libxen$(LIBNAME).so.$(MAJOR)
	rm -f headers.chk
	rm -f xen$(LIBNAME).pc

.PHONY: distclean
distclean: clean
