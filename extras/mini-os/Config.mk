#
# Compare $(1) and $(2) and replace $(2) with $(1) if they differ
#
# Typically $(1) is a newly generated file and $(2) is the target file
# being regenerated. This prevents changing the timestamp of $(2) only
# due to being auto regenereated with the same contents.
define move-if-changed
        if ! cmp -s $(1) $(2); then mv -f $(1) $(2); else rm -f $(1); fi
endef

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

# Compatibility with Xen's stubdom build environment.  If we are building
# stubdom, some XEN_ variables are set, set MINIOS_ variables accordingly.
#
ifneq ($(XEN_ROOT),)
MINI-OS_ROOT=$(XEN_ROOT)/extras/mini-os
else
MINI-OS_ROOT=$(TOPLEVEL_DIR)
endif
export MINI-OS_ROOT

ifneq ($(XEN_TARGET_ARCH),)
MINIOS_TARGET_ARCH = $(XEN_TARGET_ARCH)
else
MINIOS_COMPILE_ARCH    ?= $(shell uname -m | sed -e s/i.86/x86_32/ \
                            -e s/i86pc/x86_32/ -e s/amd64/x86_64/ \
                            -e s/armv7.*/arm32/ -e s/armv8.*/arm64/ \
                            -e s/aarch64/arm64/)

MINIOS_TARGET_ARCH     ?= $(MINIOS_COMPILE_ARCH)
endif

libc = $(stubdom)

XEN_INTERFACE_VERSION := 0x00030205
export XEN_INTERFACE_VERSION

# Try to find out the architecture family TARGET_ARCH_FAM.
# First check whether x86_... is contained (for x86_32, x86_32y, x86_64).
# If not x86 then use $(MINIOS_TARGET_ARCH)
ifeq ($(findstring x86_,$(MINIOS_TARGET_ARCH)),x86_)
TARGET_ARCH_FAM = x86
else
TARGET_ARCH_FAM = $(MINIOS_TARGET_ARCH)
endif

# The architecture family directory below mini-os.
TARGET_ARCH_DIR := arch/$(TARGET_ARCH_FAM)

# Export these variables for possible use in architecture dependent makefiles.
export TARGET_ARCH_DIR
export TARGET_ARCH_FAM

# This is used for architecture specific links.
# This can be overwritten from arch specific rules.
ARCH_LINKS =

# The path pointing to the architecture specific header files.
ARCH_INC := $(TARGET_ARCH_FAM)

# For possible special header directories.
# This can be overwritten from arch specific rules.
EXTRA_INC = $(ARCH_INC)	

# Include the architecture family's special makerules.
# This must be before include minios.mk!
include $(MINI-OS_ROOT)/$(TARGET_ARCH_DIR)/arch.mk

extra_incl := $(foreach dir,$(EXTRA_INC),-isystem $(MINI-OS_ROOT)/include/$(dir))

DEF_CPPFLAGS += -isystem $(MINI-OS_ROOT)/include
DEF_CPPFLAGS += -D__MINIOS__

ifeq ($(libc),y)
DEF_CPPFLAGS += -DHAVE_LIBC
DEF_CPPFLAGS += -isystem $(MINI-OS_ROOT)/include/posix
DEF_CPPFLAGS += -isystem $(XEN_ROOT)/tools/xenstore/include
endif

ifneq ($(LWIPDIR),)
lwip=y
DEF_CPPFLAGS += -DHAVE_LWIP
DEF_CPPFLAGS += -isystem $(LWIPDIR)/src/include
DEF_CPPFLAGS += -isystem $(LWIPDIR)/src/include/ipv4
endif
