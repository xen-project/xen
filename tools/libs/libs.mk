# Common Makefile for building a lib.
#
# Variables taken as input:
#   PKG_CONFIG_FILE: name of pkg-config file (xen$(LIBNAME).pc if empty)
#   MAJOR:   major version of lib (Xen version if empty)
#   MINOR:   minor version of lib (0 if empty)
#   version-script: Specify the name of a version script to the linker.
#     (If empty, a temporary one for unstable library is created)

LIBNAME := $(notdir $(CURDIR))

ifeq ($(origin MAJOR), undefined)
MAJOR := $(shell $(XEN_ROOT)/version.sh $(XEN_ROOT)/xen/Makefile)
endif
MINOR ?= 0

CFLAGS   += -Wmissing-prototypes
CFLAGS   += $(CFLAGS_xeninclude)
CFLAGS   += $(foreach lib, $(USELIBS_$(LIBNAME)), $(CFLAGS_libxen$(lib)))

LDLIBS += $(call xenlibs-ldlibs,$(USELIBS_$(LIBNAME)))

PIC_OBJS := $(OBJS-y:.o=.opic)

LIB_FILE_NAME = $(FILENAME_$(LIBNAME))
TARGETS := lib$(LIB_FILE_NAME).a
ifneq ($(nosharedlibs),y)
TARGETS += lib$(LIB_FILE_NAME).so
endif

version-script ?= lib$(LIB_FILE_NAME).map.tmp

PKG_CONFIG_FILE ?= $(LIB_FILE_NAME).pc
PKG_CONFIG_NAME ?= Xen$(LIBNAME)
PKG_CONFIG_DESC ?= The $(PKG_CONFIG_NAME) library for Xen hypervisor
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)
PKG_CONFIG_USELIBS := $(SHLIB_libxen$(LIBNAME))
PKG_CONFIG_LIB := $(LIB_FILE_NAME)
PKG_CONFIG_REQPRIV := $(subst $(space),$(comma),$(strip $(foreach lib,$(patsubst ctrl,control,$(USELIBS_$(LIBNAME))),xen$(lib))))

ifneq ($(CONFIG_LIBXC_MINIOS),y)
TARGETS += $(PKG_CONFIG_FILE)
$(PKG_CONFIG_FILE): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_FILE): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_FILE): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(PKG_CONFIG_DIR)/$(PKG_CONFIG_FILE)

LIBHEADER ?= $(LIB_FILE_NAME).h
LIBHEADERS = $(foreach h, $(LIBHEADER), $(XEN_INCLUDE)/$(h))

PKG_ABI := lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR)-$(XEN_TARGET_ARCH)-abi.dump

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_INCLUDE)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)

.PHONY: all
all: $(TARGETS) $(PKG_CONFIG_LOCAL) $(LIBHEADERS)

ifneq ($(NO_HEADERS_CHK),y)
all: headers.chk

headers.chk: $(LIBHEADERS) $(AUTOINCS)
	for i in $(filter %.h,$^); do \
	    $(CC) -x c -ansi -Wall -Werror $(CFLAGS_xeninclude) \
	          -S -o /dev/null $$i || exit 1; \
	    echo $$i; \
	done >$@.new
	mv $@.new $@
endif

headers.lst: FORCE
	@{ set -e; $(foreach h,$(LIBHEADERS),echo $(h);) } > $@.tmp
	@$(call move-if-changed,$@.tmp,$@)

lib$(LIB_FILE_NAME).map.tmp: FORCE
	echo 'lib$(LIB_FILE_NAME)_$(MAJOR).$(MINOR) { global: *; };' >$(@D)/.$(@F)
	$(call move-if-changed,$(@D)/.$(@F),$@)

lib$(LIB_FILE_NAME).a: $(OBJS-y)
	$(AR) rc $@ $^

lib$(LIB_FILE_NAME).so: lib$(LIB_FILE_NAME).so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
lib$(LIB_FILE_NAME).so.$(MAJOR): lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR): $(PIC_OBJS) $(version-script)
	$(CC) $(LDFLAGS) $(PTHREAD_LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,lib$(LIB_FILE_NAME).so.$(MAJOR) -Wl,--version-script=$(version-script) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(LDLIBS) $(APPEND_LDFLAGS)

# If abi-dumper is available, write out the ABI analysis
ifneq ($(ABI_DUMPER),)
ifneq ($(nosharedlibs),y)
all: $(PKG_ABI)
$(PKG_ABI): lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR) headers.lst
	$(ABI_DUMPER) $< -o $@ -public-headers headers.lst -lver $(MAJOR).$(MINOR)
endif
endif

.PHONY: install
install:: all
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) lib$(LIB_FILE_NAME).a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/lib$(LIB_FILE_NAME).so.$(MAJOR)
	$(SYMLINK_SHLIB) lib$(LIB_FILE_NAME).so.$(MAJOR) $(DESTDIR)$(libdir)/lib$(LIB_FILE_NAME).so
	for i in $(LIBHEADERS); do $(INSTALL_DATA) $$i $(DESTDIR)$(includedir); done
	$(INSTALL_DATA) $(PKG_CONFIG_FILE) $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uninstall
uninstall::
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
clean::
	rm -rf $(TARGETS) *~ $(DEPS_RM) $(OBJS-y) $(PIC_OBJS)
	rm -f lib$(LIB_FILE_NAME).so.$(MAJOR).$(MINOR) lib$(LIB_FILE_NAME).so.$(MAJOR)
	rm -f headers.chk headers.lst lib*.map.tmp .*.tmp

.PHONY: distclean
distclean: clean

ifeq ($(filter clean distclean,$(MAKECMDGOALS)),)
-include $(DEPS_INCLUDE)
endif
