#  -*- mode: Makefile; -*-

# `all' is the default target
all:

-include $(XEN_ROOT)/config/Tools.mk
include $(XEN_ROOT)/Config.mk

export _INSTALL := $(INSTALL)
INSTALL = $(XEN_ROOT)/tools/cross-install

XEN_INCLUDE        = $(XEN_ROOT)/tools/include
XEN_LIBXENTOOLLOG  = $(XEN_ROOT)/tools/libs/toollog
XEN_LIBXENEVTCHN   = $(XEN_ROOT)/tools/libs/evtchn
XEN_LIBXENGNTTAB   = $(XEN_ROOT)/tools/libs/gnttab
XEN_LIBXENCALL     = $(XEN_ROOT)/tools/libs/call
XEN_LIBXENFOREIGNMEMORY = $(XEN_ROOT)/tools/libs/foreignmemory
XEN_LIBXC          = $(XEN_ROOT)/tools/libxc
XEN_XENLIGHT       = $(XEN_ROOT)/tools/libxl
XEN_XENSTORE       = $(XEN_ROOT)/tools/xenstore
XEN_LIBXENSTAT     = $(XEN_ROOT)/tools/xenstat/libxenstat/src
XEN_BLKTAP2        = $(XEN_ROOT)/tools/blktap2
XEN_LIBVCHAN       = $(XEN_ROOT)/tools/libvchan

CFLAGS_xeninclude = -I$(XEN_INCLUDE)

XENSTORE_XENSTORED ?= y

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
LDLIBS_libxentoollog = $(XEN_LIBXENTOOLLOG)/libxentoollog$(libextension)
SHLIB_libxentoollog  = -Wl,-rpath-link=$(XEN_LIBXENTOOLLOG)

CFLAGS_libxenevtchn = -I$(XEN_LIBXENEVTCHN)/include $(CFLAGS_xeninclude)
SHDEPS_libxenevtchn =
LDLIBS_libxenevtchn = $(XEN_LIBXENEVTCHN)/libxenevtchn$(libextension)
SHLIB_libxenevtchn  = -Wl,-rpath-link=$(XEN_LIBXENEVTCHN)

CFLAGS_libxengnttab = -I$(XEN_LIBXENGNTTAB)/include $(CFLAGS_xeninclude)
SHDEPS_libxengnttab = $(SHLIB_libxentoollog)
LDLIBS_libxengnttab = $(SHDEPS_libxengnttab) $(XEN_LIBXENGNTTAB)/libxengnttab$(libextension)
SHLIB_libxengnttab  = $(SHDEPS_libxengnttab) -Wl,-rpath-link=$(XEN_LIBXENGNTTAB)

# xengntshr_* interfaces are actually part of libxengnttab.so
CFLAGS_libxengntshr = -I$(XEN_LIBXENGNTTAB)/include $(CFLAGS_xeninclude)
LDLIBS_libxengntshr = $(XEN_LIBXENGNTTAB)/libxengnttab$(libextension)
SHLIB_libxengntshr  = -Wl,-rpath-link=$(XEN_LIBXENGNTTAB)

CFLAGS_libxencall = -I$(XEN_LIBXENCALL)/include $(CFLAGS_xeninclude)
LDLIBS_libxencall = $(XEN_LIBXENCALL)/libxencall$(libextension)
SHLIB_libxencall  = -Wl,-rpath-link=$(XEN_LIBXENCALL)

CFLAGS_libxenforeignmemory = -I$(XEN_LIBXENFOREIGNMEMORY)/include $(CFLAGS_xeninclude)
LDLIBS_libxenforeignmemory = $(XEN_LIBXENFOREIGNMEMORY)/libxenforeignmemory$(libextension)
SHLIB_libxenforeignmemory  = -Wl,-rpath-link=$(XEN_LIBXENFOREIGNMEMORY)

# code which compiles against libxenctrl get __XEN_TOOLS__ and
# therefore sees the unstable hypercall interfaces.
CFLAGS_libxenctrl = -I$(XEN_LIBXC)/include $(CFLAGS_libxentoollog) $(CFLAGS_libxenforeignmemory) $(CFLAGS_xeninclude) -D__XEN_TOOLS__
SHDEPS_libxenctrl = $(SHLIB_libxentoollog) $(SHLIB_libxenevtchn) $(SHLIB_libxengnttab) $(SHLIB_libxengntshr) $(SHLIB_libxencall) $(SHLIB_libxenforeignmemory)
LDLIBS_libxenctrl = $(SHDEPS_libxenctrl) $(XEN_LIBXC)/libxenctrl$(libextension)
SHLIB_libxenctrl  = $(SHDEPS_libxenctrl) -Wl,-rpath-link=$(XEN_LIBXC)

CFLAGS_libxenguest = -I$(XEN_LIBXC)/include $(CFLAGS_libxenevtchn) $(CFLAGS_libxenforeignmemory) $(CFLAGS_xeninclude)
SHDEPS_libxenguest = $(SHLIB_libxenevtchn)
LDLIBS_libxenguest = $(SHDEPS_libxenguest) $(XEN_LIBXC)/libxenguest$(libextension)
SHLIB_libxenguest  = $(SHDEPS_libxenguest) -Wl,-rpath-link=$(XEN_LIBXC)

CFLAGS_libxenstore = -I$(XEN_XENSTORE)/include $(CFLAGS_xeninclude)
SHDEPS_libxenstore =
LDLIBS_libxenstore = $(SHDEPS_libxenguest) $(XEN_XENSTORE)/libxenstore$(libextension)
SHLIB_libxenstore  = $(SHDEPS_libxenguest) -Wl,-rpath-link=$(XEN_XENSTORE)

CFLAGS_libxenstat  = -I$(XEN_LIBXENSTAT)
SHDEPS_libxenstat  = $(SHLIB_libxenctrl) $(SHLIB_libxenstore)
LDLIBS_libxenstat  = $(SHDEPS_libxenstat) $(XEN_LIBXENSTAT)/libxenstat$(libextension)
SHLIB_libxenstat   = $(SHDEPS_libxenstat) -Wl,-rpath-link=$(XEN_LIBXENSTAT)

CFLAGS_libxenvchan = -I$(XEN_LIBVCHAN)
SHDEPS_libxenvchan = $(SHLIB_libxentoollog) $(SHLIB_libxenstore) $(SHLIB_libxenevtchn) $(SHLIB_libxengnttab) $(SHLIB_libxengntshr)
LDLIBS_libxenvchan = $(SHDEPS_libxenvchan) $(XEN_LIBVCHAN)/libxenvchan$(libextension)
SHLIB_libxenvchan  = $(SHDEPS_libxenvchan) -Wl,-rpath-link=$(XEN_LIBVCHAN)

ifeq ($(debug),y)
# Disable optimizations and enable debugging information for macros
CFLAGS += -O0 -g3 -fno-omit-frame-pointer
# But allow an override to -O0 in case Python enforces -D_FORTIFY_SOURCE=<n>.
PY_CFLAGS += $(PY_NOOPT_CFLAGS)
else
CFLAGS += -O2 -fomit-frame-pointer
endif

LIBXL_BLKTAP ?= $(CONFIG_BLKTAP2)

ifeq ($(LIBXL_BLKTAP),y)
CFLAGS_libblktapctl = -I$(XEN_BLKTAP2)/control -I$(XEN_BLKTAP2)/include $(CFLAGS_xeninclude)
SHDEPS_libblktapctl =
LDLIBS_libblktapctl = $(SHDEPS_libblktapctl) $(XEN_BLKTAP2)/control/libblktapctl$(libextension)
SHLIB_libblktapctl  = $(SHDEPS_libblktapctl) -Wl,-rpath-link=$(XEN_BLKTAP2)/control
else
CFLAGS_libblktapctl =
SHDEPS_libblktapctl =
LDLIBS_libblktapctl =
SHLIB_libblktapctl  =
endif

CFLAGS_libxenlight = -I$(XEN_XENLIGHT) $(CFLAGS_libxenctrl) $(CFLAGS_xeninclude)
SHDEPS_libxenlight = $(SHLIB_libxenctrl) $(SHLIB_libxenstore) $(SHLIB_libblktapctl)
LDLIBS_libxenlight = $(SHDEPS_libxenlight) $(XEN_XENLIGHT)/libxenlight$(libextension)
SHLIB_libxenlight  = $(SHDEPS_libxenlight) -Wl,-rpath-link=$(XEN_XENLIGHT)

CFLAGS += -D__XEN_INTERFACE_VERSION__=__XEN_LATEST_INTERFACE_VERSION__

# Get gcc to generate the dependencies for us.
CFLAGS += -MMD -MF .$(if $(filter-out .,$(@D)),$(subst /,@,$(@D))@)$(@F).d
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

subdirs-all subdirs-clean subdirs-install subdirs-distclean: .phony
	@set -e; for subdir in $(SUBDIRS) $(SUBDIRS-y); do \
		$(MAKE) subdir-$(patsubst subdirs-%,%,$@)-$$subdir; \
	done

subdir-all-% subdir-clean-% subdir-install-%: .phony
	$(MAKE) -C $* $(patsubst subdir-%-$*,%,$@)

subdir-distclean-%: .phony
	$(MAKE) -C $* distclean

ifeq (,$(findstring clean,$(MAKECMDGOALS)))
$(XEN_ROOT)/config/Tools.mk:
	$(error You have to run ./configure before building or installing the tools)
endif
