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
CFLAGS  += -fomit-frame-pointer -I$(BASEDIR)/include -D__KERNEL__ -DNDEBUG
#CFLAGS  += -fomit-frame-pointer -I$(BASEDIR)/include -D__KERNEL__
CFLAGS  += -Wno-pointer-arith -Wredundant-decls -m32
TARGET_CPU := i686
CFLAGS += -march=$(TARGET_CPU)
LDARCHFLAGS := --oformat elf32-i386 
LDFLAGS := -T xen.lds -N 


