COMPILE_ARCH := $(shell uname -m | sed -e s/i.86/i386/)
TARGET_ARCH  ?= $(COMPILE_ARCH)

nodev ?= n

TARGET  := $(BASEDIR)/xen
HDRS    := $(wildcard $(BASEDIR)/include/xen/*.h)
HDRS    += $(wildcard $(BASEDIR)/include/scsi/*.h)
HDRS    += $(wildcard $(BASEDIR)/include/hypervisor-ifs/*.h)
HDRS    += $(wildcard $(BASEDIR)/include/asm-$(TARGET_ARCH)/*.h)
# compile.h is always regenerated, but other files shouldn't be rebuilt
HDRS    := $(subst $(BASEDIR)/include/xen/compile.h,,$(HDRS))

C_SRCS  := $(wildcard *.c)
S_SRCS  := $(wildcard *.S)
OBJS    := $(patsubst %.S,%.o,$(S_SRCS))
OBJS    += $(patsubst %.c,%.o,$(C_SRCS))

# Note that link order matters!
ALL_OBJS := $(BASEDIR)/common/common.o
ALL_OBJS += $(BASEDIR)/drivers/char/driver.o
ALL_OBJS += $(BASEDIR)/drivers/pci/driver.o
ifneq ($(nodev),y)
ALL_OBJS += $(BASEDIR)/net/network.o
ALL_OBJS += $(BASEDIR)/drivers/net/driver.o
ALL_OBJS += $(BASEDIR)/drivers/block/driver.o
ALL_OBJS += $(BASEDIR)/drivers/cdrom/driver.o
ALL_OBJS += $(BASEDIR)/drivers/ide/driver.o
ALL_OBJS += $(BASEDIR)/drivers/scsi/driver.o
ALL_OBJS += $(BASEDIR)/drivers/message/fusion/driver.o
endif
ALL_OBJS += $(BASEDIR)/arch/$(TARGET_ARCH)/arch.o

HOSTCC     = gcc
HOSTCFLAGS = -Wall -Wstrict-prototypes -O2 -fomit-frame-pointer 

include $(BASEDIR)/arch/$(TARGET_ARCH)/Rules.mk

ifneq ($(debug),y)
CFLAGS += -DNDEBUG
endif

ifeq ($(nperfc),y)
CFLAGS += -DNPERFC
endif

ifeq ($(nodev),y)
CFLAGS += -DNO_DEVICES_IN_XEN
endif

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S $(HDRS) Makefile
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@

