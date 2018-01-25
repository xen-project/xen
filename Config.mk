# -*- mode: Makefile; -*-

ifeq ($(filter /%,$(XEN_ROOT)),)
$(error XEN_ROOT must be absolute)
endif

# Convenient variables
comma   := ,
squote  := '
empty   :=
space   := $(empty) $(empty)

# fallback for older make
realpath = $(wildcard $(foreach file,$(1),$(shell cd -P $(dir $(file)) && echo "$$PWD/$(notdir $(file))")))
or       = $(if $(strip $(1)),$(1),$(if $(strip $(2)),$(2),$(if $(strip $(3)),$(3),$(if $(strip $(4)),$(4)))))

-include $(XEN_ROOT)/.config

XEN_COMPILE_ARCH    ?= $(shell uname -m | sed -e s/i.86/x86_32/ \
                         -e s/i86pc/x86_32/ -e s/amd64/x86_64/ \
                         -e s/armv7.*/arm32/ -e s/armv8.*/arm64/ \
                         -e s/aarch64/arm64/)

XEN_TARGET_ARCH     ?= $(XEN_COMPILE_ARCH)
XEN_OS              ?= $(shell uname -s)

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
	sed "s! $$PWD/! !" $^ >$@.tmp && mv -f $@.tmp $@

include $(XEN_ROOT)/config/$(XEN_OS).mk
include $(XEN_ROOT)/config/$(XEN_TARGET_ARCH).mk

# arguments: variable, common path part, path to test, if yes, if no
define setvar_dir
  ifndef $(1)
    ifneq (,$(wildcard $(2)$(3)))
      $(1) ?= $(2)$(4)
    else
      $(1) ?= $(2)$(5)
    endif
  endif
endef

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
# This is complicated by the fact that unrecognised -Wno-* options:
#   (a) are ignored unless the compilation emits a warning; and
#   (b) even then produce a warning rather than an error
# To handle this we do a test compile, passing the option-under-test, on a code
# fragment that will always produce a warning (integer assigned to pointer).
# We then grep for the option-under-test in the compiler's output, the presence
# of which would indicate an "unrecognized command-line option" warning/error.
#
# Usage: cflags-y += $(call cc-option,$(CC),-march=winchip-c6,-march=i586)
cc-option = $(shell if test -z "`echo 'void*p=1;' | \
              $(1) $(2) -S -o /dev/null -x c - 2>&1 | grep -- $(2) -`"; \
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

# cc-ifversion: Check compiler version and take branch accordingly
# Usage $(call cc-ifversion,lt,0x040700,string_if_y,string_if_n)
cc-ifversion = $(shell [ $(call cc-ver,$(CC),$(1),$(2)) = "y" ] \
				&& echo $(3) || echo $(4))

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

ifndef XEN_HAS_CHECKPOLICY
    CHECKPOLICY ?= checkpolicy
    XEN_HAS_CHECKPOLICY := $(shell $(CHECKPOLICY) -h 2>&1 | grep -q xen && echo y || echo n)
    export XEN_HAS_CHECKPOLICY
endif

# as-insn: Check whether assembler supports an instruction.
# Usage: cflags-y += $(call as-insn "insn",option-yes,option-no)
as-insn = $(if $(shell echo 'void _(void) { asm volatile ( $(2) ); }' \
                       | $(1) $(filter-out -M% %.d -include %/include/xen/config.h,$(AFLAGS)) \
                              -c -x c -o /dev/null - 2>&1),$(4),$(3))

# as-insn-check: Add an option to compilation flags, but only if insn is
#                supported by assembler.
# Usage: $(call as-insn-check CFLAGS,CC,"nop",-DHAVE_GAS_NOP)
as-insn-check = $(eval $(call as-insn-check-closure,$(1),$(2),$(3),$(4)))
define as-insn-check-closure
    ifeq ($$(call as-insn,$$($(2)),$(3),y,n),y)
        $(1) += $(4)
    endif
endef

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

buildmakevars2header = $(eval $(call buildmakevars2header-closure,$(1)))
define buildmakevars2header-closure
    $(1): .phony
	rm -f $(1).tmp; \
	$(foreach var, $(BUILD_MAKE_VARS), \
	          echo "#define $(var) \"$($(var))\"" >>$(1).tmp;) \
	$(call move-if-changed,$(1).tmp,$(1))
endef

CFLAGS += -fno-strict-aliasing

CFLAGS += -std=gnu99

CFLAGS += -Wall -Wstrict-prototypes

$(call cc-option-add,HOSTCFLAGS,HOSTCC,-Wdeclaration-after-statement)
$(call cc-option-add,CFLAGS,CC,-Wdeclaration-after-statement)
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

EMBEDDED_EXTRA_CFLAGS := -nopie -fno-stack-protector -fno-stack-protector-all
EMBEDDED_EXTRA_CFLAGS += -fno-exceptions

XEN_EXTFILES_URL ?= http://xenbits.xen.org/xen-extfiles
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

ifeq ($(GIT_HTTP),y)
OVMF_UPSTREAM_URL ?= http://xenbits.xen.org/git-http/ovmf.git
QEMU_UPSTREAM_URL ?= http://xenbits.xen.org/git-http/qemu-xen.git
QEMU_TRADITIONAL_URL ?= http://xenbits.xen.org/git-http/qemu-xen-traditional.git
SEABIOS_UPSTREAM_URL ?= http://xenbits.xen.org/git-http/seabios.git
MINIOS_UPSTREAM_URL ?= http://xenbits.xen.org/git-http/mini-os.git
else
OVMF_UPSTREAM_URL ?= git://xenbits.xen.org/ovmf.git
QEMU_UPSTREAM_URL ?= git://xenbits.xen.org/qemu-xen.git
QEMU_TRADITIONAL_URL ?= git://xenbits.xen.org/qemu-xen-traditional.git
SEABIOS_UPSTREAM_URL ?= git://xenbits.xen.org/seabios.git
MINIOS_UPSTREAM_URL ?= git://xenbits.xen.org/mini-os.git
endif
OVMF_UPSTREAM_REVISION ?= 947f3737abf65fda63f3ffd97fddfa6986986868
QEMU_UPSTREAM_REVISION ?= master
MINIOS_UPSTREAM_REVISION ?= 0b4b7897e08b967a09bed2028a79fabff82342dd
# Mon Oct 16 16:36:41 2017 +0100
# Update Xen header files again

SEABIOS_UPSTREAM_REVISION ?= rel-1.10.2
# Wed Jun 22 14:53:24 2016 +0800
# fw/msr_feature_control: add support to set MSR_IA32_FEATURE_CONTROL

ETHERBOOT_NICS ?= rtl8139 8086100e


QEMU_TRADITIONAL_REVISION ?= c8ea0457495342c417c3dc033bba25148b279f60
# Fri Sep 15 19:37:27 2017 +0100
# qemu-xen-traditional: Link against xentoolcore

# Specify which qemu-dm to use. This may be `ioemu' to use the old
# Mercurial in-tree version, or a local directory, or a git URL.
# QEMU_UPSTREAM_LOC ?= `pwd`/$(XEN_ROOT)/../qemu-xen.git

# Defaults for subtree locations
QEMU_TRADITIONAL_LOC ?= $(call or,$(wildcard $(QEMU_TRADITIONAL_INTREE)),\
                                  $(QEMU_TRADITIONAL_URL))

QEMU_UPSTREAM_LOC ?= $(call or,$(wildcard $(QEMU_UPSTREAM_INTREE)),\
                               $(QEMU_UPSTREAM_URL))

# Short answer -- do not enable this unless you know what you are
# doing and are prepared for some pain.

CONFIG_TESTS       ?= y
