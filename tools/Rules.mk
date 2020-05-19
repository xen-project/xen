#  -*- mode: Makefile; -*-

# `all' is the default target
all:

-include $(XEN_ROOT)/config/Tools.mk
include $(XEN_ROOT)/Config.mk

export _INSTALL := $(INSTALL)
INSTALL = $(XEN_ROOT)/tools/cross-install

LDFLAGS += $(PREPEND_LDFLAGS_XEN_TOOLS)

XEN_INCLUDE        = $(XEN_ROOT)/tools/include
XEN_LIBXENTOOLCORE  = $(XEN_ROOT)/tools/libs/toolcore
XEN_LIBXENTOOLLOG  = $(XEN_ROOT)/tools/libs/toollog
XEN_LIBXENEVTCHN   = $(XEN_ROOT)/tools/libs/evtchn
XEN_LIBXENGNTTAB   = $(XEN_ROOT)/tools/libs/gnttab
XEN_LIBXENCALL     = $(XEN_ROOT)/tools/libs/call
XEN_LIBXENFOREIGNMEMORY = $(XEN_ROOT)/tools/libs/foreignmemory
XEN_LIBXENDEVICEMODEL = $(XEN_ROOT)/tools/libs/devicemodel
XEN_LIBXC          = $(XEN_ROOT)/tools/libxc
XEN_XENLIGHT       = $(XEN_ROOT)/tools/libxl
# Currently libxlutil lives in the same directory as libxenlight
XEN_XLUTIL         = $(XEN_XENLIGHT)
XEN_XENSTORE       = $(XEN_ROOT)/tools/xenstore
XEN_LIBXENSTAT     = $(XEN_ROOT)/tools/xenstat/libxenstat/src
XEN_LIBVCHAN       = $(XEN_ROOT)/tools/libvchan

CFLAGS_xeninclude = -I$(XEN_INCLUDE)

XENSTORE_XENSTORED ?= y

# A debug build of tools?
debug ?= y
debug_symbols ?= $(debug)

XEN_GOPATH        = $(XEN_ROOT)/tools/golang
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

CFLAGS_libxentoollog = -I$(XEN_LIBXENTOOLLOG)/include $(CFLAGS_xeninclude)
SHDEPS_libxentoollog =
LDLIBS_libxentoollog = $(SHDEPS_libxentoollog) $(XEN_LIBXENTOOLLOG)/libxentoollog$(libextension)
SHLIB_libxentoollog  = $(SHDEPS_libxentoollog) -Wl,-rpath-link=$(XEN_LIBXENTOOLLOG)

CFLAGS_libxentoolcore = -I$(XEN_LIBXENTOOLCORE)/include $(CFLAGS_xeninclude)
SHDEPS_libxentoolcore =
LDLIBS_libxentoolcore = $(SHDEPS_libxentoolcore) $(XEN_LIBXENTOOLCORE)/libxentoolcore$(libextension)
SHLIB_libxentoolcore  = $(SHDEPS_libxentoolcore) -Wl,-rpath-link=$(XEN_LIBXENTOOLCORE)

CFLAGS_libxenevtchn = -I$(XEN_LIBXENEVTCHN)/include $(CFLAGS_xeninclude)
SHDEPS_libxenevtchn = $(SHLIB_libxentoolcore)
LDLIBS_libxenevtchn = $(SHDEPS_libxenevtchn) $(XEN_LIBXENEVTCHN)/libxenevtchn$(libextension)
SHLIB_libxenevtchn  = $(SHDEPS_libxenevtchn) -Wl,-rpath-link=$(XEN_LIBXENEVTCHN)

CFLAGS_libxengnttab = -I$(XEN_LIBXENGNTTAB)/include $(CFLAGS_xeninclude)
SHDEPS_libxengnttab = $(SHLIB_libxentoollog) $(SHLIB_libxentoolcore)
LDLIBS_libxengnttab = $(SHDEPS_libxengnttab) $(XEN_LIBXENGNTTAB)/libxengnttab$(libextension)
SHLIB_libxengnttab  = $(SHDEPS_libxengnttab) -Wl,-rpath-link=$(XEN_LIBXENGNTTAB)

CFLAGS_libxencall = -I$(XEN_LIBXENCALL)/include $(CFLAGS_xeninclude)
SHDEPS_libxencall = $(SHLIB_libxentoolcore)
LDLIBS_libxencall = $(SHDEPS_libxencall) $(XEN_LIBXENCALL)/libxencall$(libextension)
SHLIB_libxencall  = $(SHDEPS_libxencall) -Wl,-rpath-link=$(XEN_LIBXENCALL)

CFLAGS_libxenforeignmemory = -I$(XEN_LIBXENFOREIGNMEMORY)/include $(CFLAGS_xeninclude)
SHDEPS_libxenforeignmemory = $(SHLIB_libxentoolcore)
LDLIBS_libxenforeignmemory = $(SHDEPS_libxenforeignmemory) $(XEN_LIBXENFOREIGNMEMORY)/libxenforeignmemory$(libextension)
SHLIB_libxenforeignmemory  = $(SHDEPS_libxenforeignmemory) -Wl,-rpath-link=$(XEN_LIBXENFOREIGNMEMORY)

CFLAGS_libxendevicemodel = -I$(XEN_LIBXENDEVICEMODEL)/include $(CFLAGS_xeninclude)
SHDEPS_libxendevicemodel = $(SHLIB_libxentoollog) $(SHLIB_libxentoolcore) $(SHLIB_xencall)
LDLIBS_libxendevicemodel = $(SHDEPS_libxendevicemodel) $(XEN_LIBXENDEVICEMODEL)/libxendevicemodel$(libextension)
SHLIB_libxendevicemodel  = $(SHDEPS_libxendevicemodel) -Wl,-rpath-link=$(XEN_LIBXENDEVICEMODEL)

# code which compiles against libxenctrl get __XEN_TOOLS__ and
# therefore sees the unstable hypercall interfaces.
CFLAGS_libxenctrl = -I$(XEN_LIBXC)/include $(CFLAGS_libxentoollog) $(CFLAGS_libxenforeignmemory) $(CFLAGS_libxendevicemodel) $(CFLAGS_xeninclude) -D__XEN_TOOLS__
SHDEPS_libxenctrl = $(SHLIB_libxentoollog) $(SHLIB_libxenevtchn) $(SHLIB_libxengnttab) $(SHLIB_libxencall) $(SHLIB_libxenforeignmemory) $(SHLIB_libxendevicemodel)
LDLIBS_libxenctrl = $(SHDEPS_libxenctrl) $(XEN_LIBXC)/libxenctrl$(libextension)
SHLIB_libxenctrl  = $(SHDEPS_libxenctrl) -Wl,-rpath-link=$(XEN_LIBXC)

CFLAGS_libxenguest = -I$(XEN_LIBXC)/include $(CFLAGS_libxenevtchn) $(CFLAGS_libxenforeignmemory) $(CFLAGS_xeninclude)
SHDEPS_libxenguest = $(SHLIB_libxenevtchn)
LDLIBS_libxenguest = $(SHDEPS_libxenguest) $(XEN_LIBXC)/libxenguest$(libextension)
SHLIB_libxenguest  = $(SHDEPS_libxenguest) -Wl,-rpath-link=$(XEN_LIBXC)

CFLAGS_libxenstore = -I$(XEN_XENSTORE)/include $(CFLAGS_xeninclude)
SHDEPS_libxenstore = $(SHLIB_libxentoolcore)
LDLIBS_libxenstore = $(SHDEPS_libxenstore) $(XEN_XENSTORE)/libxenstore$(libextension)
SHLIB_libxenstore  = $(SHDEPS_libxenstore) -Wl,-rpath-link=$(XEN_XENSTORE)
ifeq ($(CONFIG_Linux),y)
LDLIBS_libxenstore += -ldl
endif

CFLAGS_libxenstat  = -I$(XEN_LIBXENSTAT)
SHDEPS_libxenstat  = $(SHLIB_libxenctrl) $(SHLIB_libxenstore)
LDLIBS_libxenstat  = $(SHDEPS_libxenstat) $(XEN_LIBXENSTAT)/libxenstat$(libextension)
SHLIB_libxenstat   = $(SHDEPS_libxenstat) -Wl,-rpath-link=$(XEN_LIBXENSTAT)

CFLAGS_libxenvchan = -I$(XEN_LIBVCHAN) $(CFLAGS_libxengnttab) $(CFLAGS_libxenevtchn)
SHDEPS_libxenvchan = $(SHLIB_libxentoollog) $(SHLIB_libxenstore) $(SHLIB_libxenevtchn) $(SHLIB_libxengnttab)
LDLIBS_libxenvchan = $(SHDEPS_libxenvchan) $(XEN_LIBVCHAN)/libxenvchan$(libextension)
SHLIB_libxenvchan  = $(SHDEPS_libxenvchan) -Wl,-rpath-link=$(XEN_LIBVCHAN)

ifeq ($(debug),y)
# Disable optimizations
CFLAGS += -O0 -fno-omit-frame-pointer
# But allow an override to -O0 in case Python enforces -D_FORTIFY_SOURCE=<n>.
PY_CFLAGS += $(PY_NOOPT_CFLAGS)
else
CFLAGS += -O2 -fomit-frame-pointer
endif

CFLAGS_libxenlight = -I$(XEN_XENLIGHT) $(CFLAGS_libxenctrl) $(CFLAGS_xeninclude)
SHDEPS_libxenlight = $(SHLIB_libxenctrl) $(SHLIB_libxenstore)
LDLIBS_libxenlight = $(SHDEPS_libxenlight) $(XEN_XENLIGHT)/libxenlight$(libextension)
SHLIB_libxenlight  = $(SHDEPS_libxenlight) -Wl,-rpath-link=$(XEN_XENLIGHT)

CFLAGS_libxlutil = -I$(XEN_XLUTIL)
SHDEPS_libxlutil = $(SHLIB_libxenlight)
LDLIBS_libxlutil = $(SHDEPS_libxlutil) $(XEN_XLUTIL)/libxlutil$(libextension)
SHLIB_libxlutil  = $(SHDEPS_libxlutil) -Wl,-rpath-link=$(XEN_XLUTIL)

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
	$(CC) $(CPPFLAGS) -DPIC $(CFLAGS) $(CFLAGS.opic) -fPIC -c -o $@ $< $(APPEND_CFLAGS)

headers.chk:
	for i in $(filter %.h,$^); do \
	    $(CC) -x c -ansi -Wall -Werror $(CFLAGS_xeninclude) \
	          -S -o /dev/null $$i || exit 1; \
	    echo $$i; \
	done >$@.new
	mv $@.new $@

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

PKG_CONFIG_FILTER = $(foreach l,$(PKG_CONFIG_REMOVE),-e 's!\([ ,]\)$(l),!\1!g' -e 's![ ,]$(l)$$!!g')

$(PKG_CONFIG_DIR)/%.pc: %.pc.in Makefile $(XEN_ROOT)/tools/Rules.mk
	mkdir -p $(PKG_CONFIG_DIR)
	@sed -e 's!@@version@@!$(PKG_CONFIG_VERSION)!g' \
	     -e 's!@@prefix@@!$(PKG_CONFIG_PREFIX)!g' \
	     -e 's!@@incdir@@!$(PKG_CONFIG_INCDIR)!g' \
	     -e 's!@@libdir@@!$(PKG_CONFIG_LIBDIR)!g' \
	     -e 's!@@firmwaredir@@!$(XENFIRMWAREDIR)!g' \
	     -e 's!@@libexecbin@@!$(LIBEXEC_BIN)!g' \
	     -e 's!@@cflagslocal@@!$(PKG_CONFIG_CFLAGS_LOCAL)!g' \
	     -e 's!@@libsflag@@\([^ ]*\)!-L\1 -Wl,-rpath-link=\1!g' \
	     $(PKG_CONFIG_FILTER) < $< > $@

%.pc: %.pc.in Makefile $(XEN_ROOT)/tools/Rules.mk
	@sed -e 's!@@version@@!$(PKG_CONFIG_VERSION)!g' \
	     -e 's!@@prefix@@!$(PKG_CONFIG_PREFIX)!g' \
	     -e 's!@@incdir@@!$(PKG_CONFIG_INCDIR)!g' \
	     -e 's!@@libdir@@!$(PKG_CONFIG_LIBDIR)!g' \
	     -e 's!@@firmwaredir@@!$(XENFIRMWAREDIR)!g' \
	     -e 's!@@libexecbin@@!$(LIBEXEC_BIN)!g' \
	     -e 's!@@cflagslocal@@!!g' \
	     -e 's!@@libsflag@@!-L!g' \
	     $(PKG_CONFIG_FILTER) < $< > $@
