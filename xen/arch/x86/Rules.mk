########################################
# x86-specific definitions

CC := gcc
LD := ld

# Linker should relocate monitor to this address
MONITOR_BASE := 0xFC500000

# Bootloader should load monitor to this real address
LOAD_BASE    := 0x00100000

CFLAGS  := -nostdinc -fno-builtin -fno-common -fno-strict-aliasing -O3
CFLAGS  += -iwithprefix include -Wall -Werror -DMONITOR_BASE=$(MONITOR_BASE)
CFLAGS  += -fomit-frame-pointer -I$(BASEDIR)/include -D__KERNEL__
CFLAGS  += -Wno-pointer-arith -Wredundant-decls -D$(TARGET_SUBARCH)

LDFLAGS := -T xen.lds -N 

ifeq ($(TARGET_SUBARCH),x86_32)
CFLAGS += -m32 -march=i686
LDARCHFLAGS := --oformat elf32-i386 
endif

ifeq ($(TARGET_SUBARCH),x86_64)
CFLAGS += -m64
LDARCHFLAGS :=
endif
