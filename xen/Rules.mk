#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#
verbose     ?= n
debug       ?= n
perfc       ?= n
perfc_arrays?= n
domu_debug  ?= n
crash_debug ?= n

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

# Note that link order matters!
ALL_OBJS := $(BASEDIR)/common/common.o
ALL_OBJS += $(BASEDIR)/drivers/char/driver.o
ALL_OBJS += $(BASEDIR)/drivers/acpi/driver.o
ifneq ($(ACM_USE_SECURITY_POLICY),ACM_NULL_POLICY)
ALL_OBJS += $(BASEDIR)/acm/acm.o
endif
ALL_OBJS += $(BASEDIR)/arch/$(TARGET_ARCH)/arch.o

test-gcc-flag = $(shell $(CC) -v --help 2>&1 | grep -q " $(1) " && echo $(1))

include $(BASEDIR)/arch/$(TARGET_ARCH)/Rules.mk

ifneq ($(debug),y)
CFLAGS += -DNDEBUG
ifeq ($(verbose),y)
CFLAGS += -DVERBOSE
endif
else
CFLAGS += -g -DVERBOSE
endif

ifeq ($(domu_debug),y)
CFLAGS += -DDOMU_DEBUG
endif

ifeq ($(crash_debug),y)
CFLAGS += -g -DCRASH_DEBUG
endif

ifeq ($(perfc),y)
CFLAGS += -DPERF_COUNTERS
ifeq ($(perfc_arrays),y)
CFLAGS += -DPERF_ARRAYS
endif
endif

CFLAGS := $(strip $(CFLAGS))

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S $(HDRS) Makefile
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@
