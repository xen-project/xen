
#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#
verbose     ?= n
perfc       ?= n
perfc_arrays?= n
crash_debug ?= n

# Hardcoded configuration implications and dependencies.
# Do this is a neater way if it becomes unwieldy.
ifeq ($(debug),y)
verbose := y
endif
ifeq ($(perfc_arrays),y)
perfc := y
endif

XEN_ROOT=$(BASEDIR)/..
include $(XEN_ROOT)/Config.mk

# Set ARCH/SUBARCH appropriately.
override COMPILE_SUBARCH := $(XEN_COMPILE_ARCH)
override TARGET_SUBARCH  := $(XEN_TARGET_ARCH)
override COMPILE_ARCH    := $(patsubst x86%,x86,$(XEN_COMPILE_ARCH))
override TARGET_ARCH     := $(patsubst x86%,x86,$(XEN_TARGET_ARCH))

TARGET  := $(BASEDIR)/xen
HDRS    := $(wildcard $(BASEDIR)/include/xen/*.h)
HDRS    += $(wildcard $(BASEDIR)/include/public/*.h)
HDRS    += $(wildcard $(BASEDIR)/include/asm-$(TARGET_ARCH)/*.h)
HDRS    += $(wildcard $(BASEDIR)/include/asm-$(TARGET_ARCH)/$(TARGET_SUBARCH)/*.h)
# Do not depend on auto-generated header files.
HDRS    := $(subst $(BASEDIR)/include/asm-$(TARGET_ARCH)/asm-offsets.h,,$(HDRS))
HDRS    := $(subst $(BASEDIR)/include/xen/banner.h,,$(HDRS))
HDRS    := $(subst $(BASEDIR)/include/xen/compile.h,,$(HDRS))

C_SRCS  := $(wildcard *.c)
S_SRCS  := $(wildcard *.S)
OBJS    := $(patsubst %.S,%.o,$(S_SRCS))
OBJS    += $(patsubst %.c,%.o,$(C_SRCS))

ALL_OBJS-y :=
CFLAGS-y   :=
subdirs-y  :=
subdirs-n  :=

include $(BASEDIR)/arch/$(TARGET_ARCH)/Rules.mk

# Note that link order matters!
ALL_OBJS-y               += $(BASEDIR)/common/common.o
ALL_OBJS-y               += $(BASEDIR)/drivers/char/driver.o
ALL_OBJS-$(HAS_ACPI)     += $(BASEDIR)/drivers/acpi/driver.o
ALL_OBJS-$(ACM_SECURITY) += $(BASEDIR)/acm/acm.o
ALL_OBJS-y               += $(BASEDIR)/arch/$(TARGET_ARCH)/arch.o

CFLAGS-y               += -g -D__XEN__
CFLAGS-$(ACM_SECURITY) += -DACM_SECURITY
CFLAGS-$(verbose)      += -DVERBOSE
CFLAGS-$(crash_debug)  += -DCRASH_DEBUG
CFLAGS-$(perfc)        += -DPERF_COUNTERS
CFLAGS-$(perfc_arrays) += -DPERF_ARRAYS

ALL_OBJS := $(ALL_OBJS-y)
CFLAGS   := $(strip $(CFLAGS) $(CFLAGS-y))

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S $(HDRS) Makefile
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@
