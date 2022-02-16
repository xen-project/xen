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

LIB_FILE_NAME = $(FILENAME_$(LIBNAME))
LIB := lib$(LIB_FILE_NAME).a
ifneq ($(nosharedlibs),y)
LIB += lib$(LIB_FILE_NAME).so
endif

comma:= ,
empty:=
space:= $(empty) $(empty)
PKG_CONFIG ?= $(LIB_FILE_NAME).pc
PKG_CONFIG_NAME ?= Xen$(LIBNAME)
PKG_CONFIG_DESC ?= The $(PKG_CONFIG_NAME) library for Xen hypervisor
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)
PKG_CONFIG_USELIBS := $(sort $(SHLIB_libxen$(LIBNAME)))
PKG_CONFIG_LIB := $(LIB_FILE_NAME)
PKG_CONFIG_REQPRIV := $(subst $(space),$(comma),$(strip $(foreach lib,$(patsubst ctrl,control,$(USELIBS_$(LIBNAME))),xen$(lib))))

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(PKG_CONFIG_DIR)/$(PKG_CONFIG)

LIBHEADER ?= $(LIB_FILE_NAME).h
LIBHEADERS = $(foreach h, $(LIBHEADER), $(XEN_INCLUDE)/$(h))

PKG_ABI := lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR)-$(XEN_TARGET_ARCH)-abi.dump

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_INCLUDE)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)

.PHONY: all
all: build

.PHONY: build
build: libs libxen$(LIBNAME).map $(LIBHEADERS)

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

headers.chk: $(LIBHEADERS) $(AUTOINCS)

headers.lst: FORCE
	@{ set -e; $(foreach h,$(LIBHEADERS),echo $(h);) } > $@.tmp
	@$(call move-if-changed,$@.tmp,$@)

libxen$(LIBNAME).map:
	echo 'VERS_$(MAJOR).$(MINOR) { global: *; };' >$@

lib$(LIB_FILE_NAME).a: $(LIB_OBJS)
	$(AR) rc $@ $^

lib$(LIB_FILE_NAME).so: lib$(LIB_FILE_NAME).so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
lib$(LIB_FILE_NAME).so.$(MAJOR): lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR): $(PIC_OBJS) libxen$(LIBNAME).map
	$(CC) $(LDFLAGS) $(PTHREAD_LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,lib$(LIB_FILE_NAME).so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(LDUSELIBS) $(APPEND_LDFLAGS)

# If abi-dumper is available, write out the ABI analysis
ifneq ($(ABI_DUMPER),)
ifneq ($(nosharedlibs),y)
libs: $(PKG_ABI)
$(PKG_ABI): lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR) headers.lst
	$(ABI_DUMPER) $< -o $@ -public-headers headers.lst -lver $(MAJOR).$(MINOR)
endif
endif

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) lib$(LIB_FILE_NAME).a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/lib$(LIB_FILE_NAME).so.$(MAJOR)
	$(SYMLINK_SHLIB) lib$(LIB_FILE_NAME).so.$(MAJOR) $(DESTDIR)$(libdir)/lib$(LIB_FILE_NAME).so
	for i in $(LIBHEADERS); do $(INSTALL_DATA) $$i $(DESTDIR)$(includedir); done
	$(INSTALL_DATA) $(PKG_CONFIG) $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/$(LIB_FILE_NAME).pc
	for i in $(LIBHEADER); do rm -f $(DESTDIR)$(includedir)/$$i; done
	rm -f $(DESTDIR)$(libdir)/lib$(LIB_FILE_NAME).so
	rm -f $(DESTDIR)$(libdir)/lib$(LIB_FILE_NAME).so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR)
	rm -f $(DESTDIR)$(libdir)/lib$(LIB_FILE_NAME).a

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS_RM) $(LIB_OBJS) $(PIC_OBJS)
	rm -f lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR) lib$(LIB_FILE_NAME).so.$(MAJOR)
	rm -f headers.chk headers.lst
	rm -f $(PKG_CONFIG)
	rm -f _paths.h

.PHONY: distclean
distclean: clean

.PHONY: FORCE
FORCE:

ifeq ($(filter clean distclean,$(MAKECMDGOALS)),)
-include $(DEPS_INCLUDE)
endif
