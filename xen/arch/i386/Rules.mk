########################################
# x86-specific definitions

CC := gcc
LD := ld
# Linker should relocate monitor to this address
MONITOR_BASE := 0xFC500000
# Bootloader should load monitor to this real address
LOAD_BASE    := 0x00100000
CFLAGS  := -nostdinc -fno-builtin -fno-common -fno-strict-aliasing 
CFLAGS  += -iwithprefix include -O3 -Wall -DMONITOR_BASE=$(MONITOR_BASE)
CFLAGS  += -fomit-frame-pointer -I$(BASEDIR)/include -D__KERNEL__ -DNDEBUG
#CFLAGS  += -fomit-frame-pointer -I$(BASEDIR)/include -D__KERNEL__
LDFLAGS := -T xeno.lds -N


