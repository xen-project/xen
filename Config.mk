# -*- mode: Makefile; -*-

# A debug build of Xen and tools?
debug ?= n

XEN_COMPILE_ARCH    ?= $(shell uname -m | sed -e s/i.86/x86_32/ \
                         -e s/ppc/powerpc/ -e s/i86pc/x86_32/)
XEN_TARGET_ARCH     ?= $(XEN_COMPILE_ARCH)
XEN_TARGET_X86_PAE  ?= n
XEN_OS              ?= $(shell uname -s)

CONFIG_$(XEN_OS) := y

# Tools to run on system hosting the build
HOSTCC     = gcc
HOSTCFLAGS = -Wall -Werror -Wstrict-prototypes -O2 -fomit-frame-pointer

DISTDIR     ?= $(XEN_ROOT)/dist
DESTDIR     ?= /

include $(XEN_ROOT)/config/$(XEN_OS).mk
include $(XEN_ROOT)/config/$(XEN_TARGET_ARCH).mk

ifneq ($(EXTRA_PREFIX),)
EXTRA_INCLUDES += $(EXTRA_PREFIX)/include
EXTRA_LIB += $(EXTRA_PREFIX)/$(LIBDIR)
endif

test-gcc-flag = $(shell $(1) -v --help 2>&1 | $(GREP) -q " $(2) " && echo $(2))

ifneq ($(debug),y)
CFLAGS += -DNDEBUG
else
CFLAGS += -g
endif

CFLAGS += -Wall -Wstrict-prototypes

# -Wunused-value makes GCC 4.x too aggressive for my taste: ignoring the
# result of any casted expression causes a warning.
CFLAGS += -Wno-unused-value

HOSTCFLAGS += $(call test-gcc-flag,$(HOSTCC),-Wdeclaration-after-statement)
CFLAGS     += $(call test-gcc-flag,$(CC),-Wdeclaration-after-statement)

LDFLAGS += $(foreach i, $(EXTRA_LIB), -L$(i)) 
CFLAGS += $(foreach i, $(EXTRA_INCLUDES), -I$(i))

# If ACM_SECURITY = y, then the access control module is compiled
# into Xen and the policy type can be set by the boot policy file
#        y - Build the Xen ACM framework
#        n - Do not build the Xen ACM framework
ACM_SECURITY ?= n

# If ACM_SECURITY = y and no boot policy file is installed,
# then the ACM defaults to the security policy set by
# ACM_DEFAULT_SECURITY_POLICY
# Supported models are:
#	ACM_NULL_POLICY
#	ACM_CHINESE_WALL_POLICY
#	ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY
#	ACM_CHINESE_WALL_AND_SIMPLE_TYPE_ENFORCEMENT_POLICY
ACM_DEFAULT_SECURITY_POLICY ?= ACM_NULL_POLICY

# Optional components
XENSTAT_XENTOP ?= y

VTPM_TOOLS ?= n

-include $(XEN_ROOT)/.config
