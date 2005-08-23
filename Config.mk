# -*- mode: Makefile; -*-

# Currently supported architectures: x86_32, x86_64
XEN_COMPILE_ARCH    ?= $(shell uname -m | sed -e s/i.86/x86_32/)
XEN_TARGET_ARCH     ?= $(XEN_COMPILE_ARCH)
XEN_TARGET_X86_PAE  ?= n

# Tools to run on system hosting the build
HOSTCC     = gcc
HOSTCFLAGS = -Wall -Werror -Wstrict-prototypes -O2 -fomit-frame-pointer

AS         = $(CROSS_COMPILE)as
LD         = $(CROSS_COMPILE)ld
CC         = $(CROSS_COMPILE)gcc
CPP        = $(CROSS_COMPILE)gcc -E
AR         = $(CROSS_COMPILE)ar
RANLIB     = $(CROSS_COMPILE)ranlib
NM         = $(CROSS_COMPILE)nm
STRIP      = $(CROSS_COMPILE)strip
OBJCOPY    = $(CROSS_COMPILE)objcopy
OBJDUMP    = $(CROSS_COMPILE)objdump

ifeq ($(XEN_TARGET_ARCH),x86_64)
LIBDIR = lib64
else
LIBDIR = lib
endif

ifneq ($(EXTRA_PREFIX),)
EXTRA_INCLUDES += $(EXTRA_PREFIX)/include
EXTRA_LIB += $(EXTRA_PREFIX)/$(LIBDIR)
endif

LDFLAGS += $(foreach i, $(EXTRA_LIB), -L$(i)) 
CFLAGS += $(foreach i, $(EXTRA_INCLUDES), -I$(i))

# Choose the best mirror to download linux kernel
KERNEL_REPO = http://www.kernel.org

# ACM_USE_SECURITY_POLICY is set to security policy of Xen
# Supported models are:
#	ACM_NULL_POLICY (ACM will not be built with this policy)
#	ACM_CHINESE_WALL_POLICY
#	ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY
#	ACM_CHINESE_WALL_AND_SIMPLE_TYPE_ENFORCEMENT_POLICY
ACM_USE_SECURITY_POLICY ?= ACM_NULL_POLICY

# Optional components
XENSTAT_XENTOP ?= y

