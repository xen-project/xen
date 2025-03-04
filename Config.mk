# -*- mode: Makefile; -*-

ifeq ($(filter /%,$(XEN_ROOT)),)
$(error XEN_ROOT must be absolute)
endif

# Convenient variables
comma   := ,
open    := (
close   := )
squote  := '
#' Balancing squote, to help syntax highlighting
empty   :=
space   := $(empty) $(empty)

# fallback for older make
realpath = $(wildcard $(foreach file,$(1),$(shell cd -P $(dir $(file)) && echo "$$PWD/$(notdir $(file))")))
or       = $(if $(strip $(1)),$(1),$(if $(strip $(2)),$(2),$(if $(strip $(3)),$(3),$(if $(strip $(4)),$(4)))))

-include $(XEN_ROOT)/.config

ifeq ($(origin XEN_COMPILE_ARCH), undefined)
XEN_COMPILE_ARCH    := $(shell uname -m | sed -e s/i.86/x86_32/ \
                         -e s/i86pc/x86_32/ -e s/amd64/x86_64/ \
                         -e s/armv7.*/arm32/ -e s/armv8.*/arm64/ \
                         -e s/aarch64/arm64/)
endif

XEN_TARGET_ARCH     ?= $(XEN_COMPILE_ARCH)
ifeq ($(origin XEN_OS), undefined)
XEN_OS              := $(shell uname -s)
endif

CONFIG_$(XEN_OS) := y

SHELL     ?= /bin/sh

# Tools to run on system hosting the build
HOSTCFLAGS  = -Wall -Werror -Wstrict-prototypes -O2 -fomit-frame-pointer
HOSTCFLAGS += -fno-strict-aliasing

DISTDIR     ?= $(XEN_ROOT)/dist
DESTDIR     ?= /

# Allow phony attribute to be listed as dependency rather than fake target
.PHONY: .phony

# If we are not cross-compiling, default HOSTC{C/XX} to C{C/XX}
ifeq ($(XEN_TARGET_ARCH), $(XEN_COMPILE_ARCH))
HOSTCC ?= $(CC)
HOSTCXX ?= $(CXX)
endif

# Use Clang/LLVM instead of GCC?
clang ?= n
ifeq ($(clang),n)
gcc := y
HOSTCC ?= gcc
HOSTCXX ?= g++
else
gcc := n
HOSTCC ?= clang
HOSTCXX ?= clang++
endif

DEPS_INCLUDE = $(addsuffix .d2, $(basename $(wildcard $(DEPS))))
DEPS_RM = $(DEPS) $(DEPS_INCLUDE)

%.d2: %.d
	sed "s!\(^\| \)$$PWD/! !" $^ >$@.tmp && mv -f $@.tmp $@

include $(XEN_ROOT)/config/$(XEN_OS).mk
include $(XEN_ROOT)/config/$(XEN_TARGET_ARCH).mk

ifneq ($(EXTRA_PREFIX),)
EXTRA_INCLUDES += $(EXTRA_PREFIX)/include
EXTRA_LIB += $(EXTRA_PREFIX)/lib
endif

PYTHON      ?= python
PYTHON_PREFIX_ARG ?= --prefix="$(prefix)"
# The above requires that prefix contains *no spaces*. This variable is here
# to permit the user to set PYTHON_PREFIX_ARG to '' to workaround this bug:
#  https://bugs.launchpad.net/ubuntu/+bug/362570

# cc-option: Check if compiler supports first option, else fall back to second.
#
# This is complicated by the fact that with most gcc versions unrecognised
# -Wno-* options:
#   (a) are ignored unless the compilation emits a warning; and
#   (b) even then produce a warning rather than an error
# Further Clang also only warns for unrecognised -W* options.  To handle this
# we do a test compile, substituting -Wno-* by -W* and adding -Werror.  This
# way all unrecognised options are diagnosed uniformly, allowing us to merely
# check exit status.
#
# Usage: cflags-y += $(call cc-option,$(CC),-march=winchip-c6,-march=i586)
cc-option = $(shell if $(1) $(2:-Wno-%=-W%) -Werror -c -o /dev/null -x c /dev/null >/dev/null 2>&1; \
              then echo "$(2)"; else echo "$(3)"; fi ;)

# cc-option-add: Add an option to compilation flags, but only if supported.
# Usage: $(call cc-option-add CFLAGS,CC,-march=winchip-c6)
cc-option-add = $(eval $(call cc-option-add-closure,$(1),$(2),$(3)))
define cc-option-add-closure
    ifneq ($$(call cc-option,$$($(2)),$(3),n),n)
        $(1) += $(3)
    endif
endef

cc-options-add = $(foreach o,$(3),$(call cc-option-add,$(1),$(2),$(o)))

# cc-ver: Check compiler against the version requirement. Return boolean 'y'/'n'.
# Usage: ifeq ($(call cc-ver,$(CC),ge,0x030400),y)
cc-ver = $(shell if [ $$((`$(1) -dumpversion | awk -F. \
           '{ printf "0x%02x%02x%02x", $$1, $$2, $$3}'`)) -$(2) $$(($(3))) ]; \
           then echo y; else echo n; fi ;)

# cc-ver-check: Check compiler is at least specified version, else fail.
# Usage: $(call cc-ver-check,CC,0x030400,"Require at least gcc-3.4")
cc-ver-check = $(eval $(call cc-ver-check-closure,$(1),$(2),$(3)))
define cc-ver-check-closure
    ifeq ($$(call cc-ver,$$($(1)),ge,$(2)),n)
        override $(1) = echo "*** FATAL BUILD ERROR: "$(3) >&2; exit 1;
        cc-option := n
    endif
endef

# Require GCC v4.1+
check-$(gcc) = $(call cc-ver-check,CC,0x040100,"Xen requires at least gcc-4.1")
$(eval $(check-y))

ld-ver-build-id = $(shell $(1) --build-id 2>&1 | \
					grep -q build-id && echo n || echo y)

export XEN_HAS_BUILD_ID ?= n
ifeq ($(call ld-ver-build-id,$(LD)),n)
build_id_linker :=
else
CFLAGS += -DBUILD_ID
export XEN_HAS_BUILD_ID=y
build_id_linker := --build-id=sha1
endif

# Wrap date(1) to use SOURCE_DATE_EPOCH if set the environment.
# See https://reproducible-builds.org/docs/source-date-epoch/
ifdef SOURCE_DATE_EPOCH
date = $(shell LC_ALL=C date -u -d "@$(SOURCE_DATE_EPOCH)" $(1) 2>/dev/null || LC_ALL=C date -u -r "$(SOURCE_DATE_EPOCH)" $(1) 2>/dev/null || LC_ALL=C date -u $(1))
else
date = $(shell LC_ALL=C date $(1))
endif

define buildmakevars2shellvars
    export PREFIX="$(prefix)";                                            \
    export XEN_SCRIPT_DIR="$(XEN_SCRIPT_DIR)";                            \
    export XEN_ROOT="$(XEN_ROOT)"
endef

#
# Compare $(1) and $(2) and replace $(2) with $(1) if they differ
#
# Typically $(1) is a newly generated file and $(2) is the target file
# being regenerated. This prevents changing the timestamp of $(2) only
# due to being auto regenereated with the same contents.
define move-if-changed
	if ! cmp -s $(1) $(2); then mv -f $(1) $(2); else rm -f $(1); fi
endef

BUILD_MAKE_VARS := sbindir bindir LIBEXEC LIBEXEC_BIN libdir SHAREDIR \
                   XENFIRMWAREDIR XEN_CONFIG_DIR XEN_SCRIPT_DIR XEN_LOCK_DIR \
                   XEN_RUN_DIR XEN_PAGING_DIR XEN_DUMP_DIR XEN_LOG_DIR \
                   XEN_LIB_DIR XEN_RUN_STORED

buildmakevars2file = $(eval $(call buildmakevars2file-closure,$(1)))
define buildmakevars2file-closure
    $(1): .phony
	rm -f $(1).tmp; \
	$(foreach var, $(BUILD_MAKE_VARS), \
	          echo "$(var)=\"$($(var))\"" >>$(1).tmp;) \
	$(call move-if-changed,$(1).tmp,$(1))
endef

CFLAGS += -fno-strict-aliasing

CFLAGS += -std=gnu99

CFLAGS += -Wall -Wstrict-prototypes

$(call cc-option-add,CFLAGS,CC,-Wno-unused-but-set-variable)
$(call cc-option-add,CFLAGS,CC,-Wno-unused-local-typedefs)

LDFLAGS += $(foreach i, $(EXTRA_LIB), -L$(i)) 
CFLAGS += $(foreach i, $(EXTRA_INCLUDES), -I$(i))
LDFLAGS += $(foreach i, $(PREPEND_LIB), -L$(i))
CFLAGS += $(foreach i, $(PREPEND_INCLUDES), -I$(i))
ifeq ($(XEN_TOOLS_RPATH),y)
LDFLAGS += -Wl,-rpath,$(libdir)
endif
APPEND_LDFLAGS += $(foreach i, $(APPEND_LIB), -L$(i))
APPEND_CFLAGS += $(foreach i, $(APPEND_INCLUDES), -I$(i))

EMBEDDED_EXTRA_CFLAGS := -fno-pie -fno-stack-protector
EMBEDDED_EXTRA_CFLAGS += -fno-exceptions -fno-asynchronous-unwind-tables

XEN_EXTFILES_URL ?= https://xenbits.xen.org/xen-extfiles
# All the files at that location were downloaded from elsewhere on
# the internet.  The original download URL is preserved as a comment
# near the place in the Xen Makefiles where the file is used.

# Where to look for inlined subtrees (for example, from a tarball)
QEMU_UPSTREAM_INTREE ?= $(XEN_ROOT)/tools/qemu-xen
QEMU_TRADITIONAL_INTREE ?= $(XEN_ROOT)/tools/qemu-xen-traditional


# Handle legacy options
ifneq (,$(SEABIOS_UPSTREAM_TAG))
SEABIOS_UPSTREAM_REVISION ?= $(SEABIOS_UPSTREAM_TAG)
endif
ifneq (,$(QEMU_REMOTE))
QEMU_TRADITIONAL_URL ?= $(QEMU_REMOTE)
endif
ifneq (,$(CONFIG_QEMU))
QEMU_TRADITIONAL_LOC ?= $(CONFIG_QEMU)
endif
ifneq (,$(QEMU_TAG))
QEMU_TRADITIONAL_REVISION ?= $(QEMU_TAG)
endif

OVMF_UPSTREAM_URL ?= https://xenbits.xen.org/git-http/ovmf.git
OVMF_UPSTREAM_REVISION ?= ba91d0292e593df8528b66f99c1b0b14fadc8e16

QEMU_UPSTREAM_URL ?= https://xenbits.xen.org/git-http/qemu-xen.git
QEMU_UPSTREAM_REVISION ?= qemu-xen-4.20.0

MINIOS_UPSTREAM_URL ?= https://xenbits.xen.org/git-http/mini-os.git
MINIOS_UPSTREAM_REVISION ?= xen-RELEASE-4.20.0

SEABIOS_UPSTREAM_URL ?= https://xenbits.xen.org/git-http/seabios.git
SEABIOS_UPSTREAM_REVISION ?= rel-1.16.3

ETHERBOOT_NICS ?= rtl8139 8086100e


QEMU_TRADITIONAL_URL ?= https://xenbits.xen.org/git-http/qemu-xen-traditional.git
QEMU_TRADITIONAL_REVISION ?= xen-4.20.0
# Wed Jul 15 10:01:40 2020 +0100
# qemu-trad: remove Xen path dependencies

# Specify which qemu-dm to use. This may be `ioemu' to use the old
# Mercurial in-tree version, or a local directory, or a git URL.
# QEMU_UPSTREAM_LOC ?= `pwd`/$(XEN_ROOT)/../qemu-xen.git

# Defaults for subtree locations
QEMU_TRADITIONAL_LOC ?= $(call or,$(wildcard $(QEMU_TRADITIONAL_INTREE)),\
                                  $(QEMU_TRADITIONAL_URL))

QEMU_UPSTREAM_LOC ?= $(call or,$(wildcard $(QEMU_UPSTREAM_INTREE)),\
                               $(QEMU_UPSTREAM_URL))

CONFIG_TESTS       ?= y
