########################################
# x86-specific definitions

CC := gcc
LD := ld
# Linker should relocate monitor to this address
MONITOR_BASE := 0xE0100000
# Bootloader should load monitor to this real address
LOAD_BASE    := 0x00100000
CFLAGS  := -fno-builtin -O3 -Wall -DMONITOR_BASE=$(MONITOR_BASE) 
CFLAGS  += -I$(BASEDIR)/include -D__KERNEL__
LDFLAGS := -T xeno.lds -N


