
ARCH    := i386

TARGET  := $(BASEDIR)/image
HDRS    := $(wildcard $(BASEDIR)/include/xeno/*.h)
HDRS    += $(wildcard $(BASEDIR)/include/scsi/*.h)
HDRS    += $(wildcard $(BASEDIR)/include/hypervisor-ifs/*.h)
HDRS    += $(wildcard $(BASEDIR)/include/asm-$(ARCH)/*.h)

C_SRCS  := $(wildcard *.c)
S_SRCS  := $(wildcard *.S)
OBJS    := $(patsubst %.S,%.o,$(S_SRCS))
OBJS    += $(patsubst %.c,%.o,$(C_SRCS))

# Note that link order matters!
ALL_OBJS := $(BASEDIR)/common/common.o
ALL_OBJS += $(BASEDIR)/net/network.o
ALL_OBJS += $(BASEDIR)/drivers/pci/driver.o
ALL_OBJS += $(BASEDIR)/drivers/net/driver.o
ALL_OBJS += $(BASEDIR)/drivers/block/driver.o
ALL_OBJS += $(BASEDIR)/drivers/ide/driver.o
ALL_OBJS += $(BASEDIR)/arch/$(ARCH)/arch.o

HOSTCC     = gcc
HOSTCFLAGS = -Wall -Wstrict-prototypes -O2 -fomit-frame-pointer 

include $(BASEDIR)/arch/$(ARCH)/Rules.mk

%.o: %.c $(HDRS) Makefile
	$(CC) -g $(CFLAGS) -c $< -o $@

%.o: %.S $(HDRS) Makefile
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@

