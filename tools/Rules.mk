#  -*- mode: Makefile; -*-

# `all' is the default target
all:

-include $(XEN_ROOT)/config/Tools.mk
include $(XEN_ROOT)/Config.mk

XEN_FULLVERSION=$(shell env \
    XEN_EXTRAVERSION=$(XEN_EXTRAVERSION) \
    XEN_VENDORVERSION=$(XEN_VENDORVERSION) \
    $(SHELL) $(XEN_ROOT)/version.sh --full $(XEN_ROOT)/xen/Makefile)

export _INSTALL := $(INSTALL)
INSTALL = $(XEN_ROOT)/tools/cross-install

LDFLAGS += $(PREPEND_LDFLAGS_XEN_TOOLS)

XEN_INCLUDE        = $(XEN_ROOT)/tools/include

include $(XEN_ROOT)/tools/libs/uselibs.mk

CFLAGS_xeninclude = -I$(XEN_INCLUDE)

XENSTORE_XENSTORED ?= y

# A debug build of tools?
debug ?= y
debug_symbols ?= $(debug)

XEN_GOCODE_URL    = golang.xenproject.org

ifeq ($(debug_symbols),y)
CFLAGS += -g3
endif

ifneq ($(nosharedlibs),y)
INSTALL_SHLIB = $(INSTALL_PROG)
SYMLINK_SHLIB = ln -sf
libextension = .so
else
libextension = .a
XENSTORE_STATIC_CLIENTS=y
# If something tries to use these it is a mistake.  Provide references
# to nonexistent programs to produce a sane error message.
INSTALL_SHLIB = : install-shlib-unsupported-fail
SYMLINK_SHLIB = : symlink-shlib-unsupported-fail
endif

# Compiling and linking against in tree libraries.
#
# In order to compile and link against an in-tree library various
# cpp/compiler/linker options are required.
#
# For example consider a library "libfoo" which itself uses two other
# libraries:
#  libbar - whose use is entirely internal to libfoo and not exposed
#           to users of libfoo at all.
#  libbaz - whose use is entirely internal to libfoo but libfoo's
#           public headers include one or more of libbaz's
#           public headers. Users of libfoo are therefore transitively
#           using libbaz's header but not linking against libbaz.
#
# SHDEPS_libfoo: Flags for linking recursive dependencies of
#                libfoo. Must contain SHLIB for every library which
#                libfoo links against. So must contain both
#                $(SHLIB_libbar) and $(SHLIB_libbaz).
#
# SHLIB_libfoo: Flags for recursively linking against libfoo. Must
#               contains SHDEPS_libfoo and:
#                   -Wl,-rpath-link=<directory containing libfoo.so>
#
# CFLAGS_libfoo: Flags for compiling against libfoo. Must add the
#                directories containing libfoo's headers to the
#                include path. Must recursively include
#                $(CFLAGS_libbaz), to satisfy the transitive inclusion
#                of the headers but not $(CFLAGS_libbar) since none of
#                libbar's headers are required to build against
#                libfoo.
#
# LDLIBS_libfoo: Flags for linking against libfoo. Must contain
#                $(SHDEPS_libfoo) and the path to libfoo.so
#
# Consumers of libfoo should include $(CFLAGS_libfoo) and
# $(LDLIBS_libfoo) in their appropriate directories. They should not
# include any CFLAGS or LDLIBS relating to libbar or libbaz unless
# they use those libraries directly (not via libfoo) too.
#
# Consumers of libfoo should not directly use $(SHDEPS_libfoo) or
# $(SHLIB_libfoo)

define LIB_defs
 FILENAME_$(1) ?= xen$(1)
 XEN_libxen$(1) = $$(XEN_ROOT)/tools/libs/$(1)
 CFLAGS_libxen$(1) = $$(CFLAGS_xeninclude)
 SHDEPS_libxen$(1) = $$(foreach use,$$(USELIBS_$(1)),$$(SHLIB_libxen$$(use)))
 LDLIBS_libxen$(1) = $$(SHDEPS_libxen$(1)) $$(XEN_libxen$(1))/lib$$(FILENAME_$(1))$$(libextension)
 SHLIB_libxen$(1) = $$(SHDEPS_libxen$(1)) -Wl,-rpath-link=$$(XEN_libxen$(1))
endef

$(foreach lib,$(LIBS_LIBS),$(eval $(call LIB_defs,$(lib))))

# code which compiles against libxenctrl get __XEN_TOOLS__ and
# therefore sees the unstable hypercall interfaces.
CFLAGS_libxenctrl += -D__XEN_TOOLS__

ifeq ($(CONFIG_Linux),y)
LDLIBS_libxenstore += -ldl
endif

CFLAGS_libxenlight += $(CFLAGS_libxenctrl)

ifeq ($(debug),y)
# Use -Og if available, -O0 otherwise
dbg_opt_level := $(call cc-option,$(CC),-Og,-O0)
CFLAGS += $(dbg_opt_level) -fno-omit-frame-pointer
# But allow an override to -O0 in case Python enforces -D_FORTIFY_SOURCE=<n>.
PY_CFLAGS += $(PY_NOOPT_CFLAGS)
else
CFLAGS += -O2 -fomit-frame-pointer
endif

CFLAGS += -D__XEN_INTERFACE_VERSION__=__XEN_LATEST_INTERFACE_VERSION__

# Get gcc to generate the dependencies for us.
CFLAGS += -MMD -MP -MF .$(if $(filter-out .,$(@D)),$(subst /,@,$(@D))@)$(@F).d
DEPS = .*.d

ifneq ($(FILE_OFFSET_BITS),)
CFLAGS  += -D_FILE_OFFSET_BITS=$(FILE_OFFSET_BITS)
endif
ifneq ($(XEN_OS),NetBSD)
# Enable implicit LFS support *and* explicit LFS names.
CFLAGS  += -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
endif

# 32-bit x86 does not perform well with -ve segment accesses on Xen.
CFLAGS-$(CONFIG_X86_32) += $(call cc-option,$(CC),-mno-tls-direct-seg-refs)
CFLAGS += $(CFLAGS-y)

CFLAGS += $(EXTRA_CFLAGS_XEN_TOOLS)

INSTALL_PYTHON_PROG = \
	$(XEN_ROOT)/tools/python/install-wrap "$(PYTHON_PATH)" $(INSTALL_PROG)

%.opic: %.c
	$(CC) $(CPPFLAGS) -DPIC $(CFLAGS) $(CFLAGS_$*.opic) -fPIC -c -o $@ $< $(APPEND_CFLAGS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_$*.o) -c -o $@ $< $(APPEND_CFLAGS)

%.o: %.cc
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(CXXFLAGS_$*.o) -c -o $@ $< $(APPEND_CFLAGS)

%.o: %.S
	$(CC) $(CFLAGS) $(CFLAGS_$*.o) -c $< -o $@ $(APPEND_CFLAGS)
%.opic: %.S
	$(CC) $(CPPFLAGS) -DPIC $(CFLAGS) -fPIC -c -o $@ $< $(APPEND_CFLAGS)

subdirs-all subdirs-clean subdirs-install subdirs-distclean subdirs-uninstall: .phony
	@set -e; for subdir in $(SUBDIRS) $(SUBDIRS-y); do \
		$(MAKE) subdir-$(patsubst subdirs-%,%,$@)-$$subdir; \
	done

subdir-all-% subdir-clean-% subdir-install-% subdir-uninstall-%: .phony
	$(MAKE) -C $* $(patsubst subdir-%-$*,%,$@)

subdir-distclean-%: .phony
	$(MAKE) -C $* distclean

no-configure-targets := distclean subdir-distclean% clean subdir-clean% subtree-force-update-all %-dir-force-update
ifeq (,$(filter $(no-configure-targets),$(MAKECMDGOALS)))
$(XEN_ROOT)/config/Tools.mk:
	$(error You have to run ./configure before building or installing the tools)
endif

PKG_CONFIG_DIR ?= $(XEN_ROOT)/tools/pkg-config

$(PKG_CONFIG_DIR):
	mkdir -p $(PKG_CONFIG_DIR)

$(PKG_CONFIG_DIR)/%.pc: Makefile $(XEN_ROOT)/tools/Rules.mk $(PKG_CONFIG_DIR)
	{ \
	echo "prefix=$(PKG_CONFIG_PREFIX)"; \
	echo "includedir=$(PKG_CONFIG_INCDIR)"; \
	echo "libdir=$(PKG_CONFIG_LIBDIR)"; \
	echo ""; \
	echo "Name: $(PKG_CONFIG_NAME)"; \
	echo "Description: $(PKG_CONFIG_DESC)"; \
	echo "Version: $(PKG_CONFIG_VERSION)"; \
	echo "Cflags: -I\$${includedir}"; \
	echo "Libs: -L\$${libdir} $(PKG_CONFIG_USELIBS) -l$(PKG_CONFIG_LIB)"; \
	echo "Libs.private: $(PKG_CONFIG_LIBSPRIV)"; \
	echo "Requires.private: $(PKG_CONFIG_REQPRIV)"; \
	} > $@

%.pc: Makefile $(XEN_ROOT)/tools/Rules.mk
	{ \
	echo "prefix=$(PKG_CONFIG_PREFIX)"; \
	echo "includedir=$(PKG_CONFIG_INCDIR)"; \
	echo "libdir=$(PKG_CONFIG_LIBDIR)"; \
	echo ""; \
	echo "Name: $(PKG_CONFIG_NAME)"; \
	echo "Description: $(PKG_CONFIG_DESC)"; \
	echo "Version: $(PKG_CONFIG_VERSION)"; \
	echo "Cflags: -I\$${includedir}"; \
	echo "Libs: -L\$${libdir} -l$(PKG_CONFIG_LIB)"; \
	echo "Libs.private: $(PKG_CONFIG_LIBSPRIV)"; \
	echo "Requires.private: $(PKG_CONFIG_REQPRIV)"; \
	} > $@

.PHONY: FORCE
FORCE:
