
verbose     ?= n
debug       ?= n
perfc       ?= n
trace       ?= n
optimize    ?= y
domu_debug  ?= n
crash_debug ?= n

# Currently supported architectures: x86_32, x86_64
XEN_COMPILE_ARCH    ?= $(shell uname -m | sed -e s/i.86/x86_32/)
XEN_TARGET_ARCH     ?= $(XEN_COMPILE_ARCH)

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
ALL_OBJS += $(BASEDIR)/drivers/pci/driver.o
ALL_OBJS += $(BASEDIR)/arch/$(TARGET_ARCH)/arch.o

HOSTCC     = gcc
HOSTCFLAGS = -Wall -Wstrict-prototypes -O2 -fomit-frame-pointer 

test-gcc-flag = $(shell gcc -v --help 2>&1 | grep -q " $(1) " && echo $(1))

include $(BASEDIR)/arch/$(TARGET_ARCH)/Rules.mk

ifneq ($(debug),y)
CFLAGS += -DNDEBUG
ifeq ($(verbose),y)
CFLAGS += -DVERBOSE
endif
else
CFLAGS += -DVERBOSE
endif

ifeq ($(domu_debug),y)
CFLAGS += -DDOMU_DEBUG
endif

ifeq ($(crash_debug),y)
CFLAGS += -g -DCRASH_DEBUG
endif

ifeq ($(perfc),y)
CFLAGS += -DPERF_COUNTERS
endif

ifeq ($(trace),y)
CFLAGS += -DTRACE_BUFFER
endif

CFLAGS := $(strip $(CFLAGS))

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S $(HDRS) Makefile
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@

