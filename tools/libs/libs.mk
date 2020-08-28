# Common Makefile for building a lib.
#
# Variables taken as input:
#   PKG_CONFIG: name of pkg-config file (xen$(LIBNAME).pc if empty)
#   MAJOR:   major version of lib (Xen version if empty)
#   MINOR:   minor version of lib (0 if empty)

LIBNAME := $(notdir $(CURDIR))
MAJOR ?= $(shell $(XEN_ROOT)/version.sh $(XEN_ROOT)/xen/Makefile)
MINOR ?= 0

SHLIB_LDFLAGS += -Wl,--version-script=libxen$(LIBNAME).map

CFLAGS   += -Werror -Wmissing-prototypes
CFLAGS   += -I./include $(CFLAGS_xeninclude)
CFLAGS   += $(foreach lib, $(USELIBS_$(LIBNAME)), $(CFLAGS_libxen$(lib)))

LDUSELIBS = $(foreach lib, $(USELIBS_$(LIBNAME)), $(LDLIBS_libxen$(lib)))

LIB_OBJS := $(SRCS-y:.c=.o)
PIC_OBJS := $(SRCS-y:.c=.opic)

LIB := libxen$(LIBNAME).a
ifneq ($(nosharedlibs),y)
LIB += libxen$(LIBNAME).so
endif

comma:= ,
empty:=
space:= $(empty) $(empty)
PKG_CONFIG ?= xen$(LIBNAME).pc
PKG_CONFIG_NAME ?= Xen$(LIBNAME)
PKG_CONFIG_DESC ?= The $(PKG_CONFIG_NAME) library for Xen hypervisor
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)
PKG_CONFIG_USELIBS := $(SHLIB_libxen$(LIBNAME))
PKG_CONFIG_LIB := xen$(LIBNAME)
PKG_CONFIG_REQPRIV := $(subst $(space),$(comma),$(strip $(foreach lib,$(patsubst ctrl,control,$(USELIBS_$(LIBNAME))),xen$(lib))))

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(PKG_CONFIG_DIR)/$(PKG_CONFIG)

LIBHEADER ?= xen$(LIBNAME).h
LIBHEADERS = $(foreach h, $(LIBHEADER), include/$(h))
LIBHEADERSGLOB = $(foreach h, $(LIBHEADER), $(XEN_ROOT)/tools/include/$(h))

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)

.PHONY: all
all: build

.PHONY: build
build: libs libxen$(LIBNAME).map

.PHONY: libs
libs: headers.chk $(LIB) $(PKG_CONFIG_INST) $(PKG_CONFIG_LOCAL)

ifneq ($(NO_HEADERS_CHK),y)
headers.chk:
	for i in $(filter %.h,$^); do \
	    $(CC) -x c -ansi -Wall -Werror $(CFLAGS_xeninclude) \
	          -S -o /dev/null $$i || exit 1; \
	    echo $$i; \
	done >$@.new
	mv $@.new $@
else
.PHONY: headers.chk
endif

headers.chk: $(LIBHEADERSGLOB) $(AUTOINCS)

libxen$(LIBNAME).map:
	echo 'VERS_$(MAJOR).$(MINOR) { global: *; };' >$@

$(LIBHEADERSGLOB): $(LIBHEADERS)
	for i in $(realpath $(LIBHEADERS)); do ln -sf $$i $(XEN_ROOT)/tools/include; done

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
	for i in $(LIBHEADERS); do $(INSTALL_DATA) $$i $(DESTDIR)$(includedir); done
	$(INSTALL_DATA) $(PKG_CONFIG) $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/xen$(LIBNAME).pc
	for i in $(LIBHEADER); do rm -f $(DESTDIR)$(includedir)/$(LIBHEADER); done
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
	rm -f $(PKG_CONFIG)
	rm -f $(LIBHEADERSGLOB)
	rm -f _paths.h

.PHONY: distclean
distclean: clean
