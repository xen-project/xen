########################################
# x86-specific definitions

ifeq ($(COMPILE_ARCH),$(TARGET_ARCH))
OBJCOPY = objcopy
endif
ifneq ($(COMPILE_ARCH),$(TARGET_ARCH))
CC = /usr/local/sp_env/v2.2.5/i686/bin/ia64-unknown-linux-gcc
LD = /usr/local/sp_env/v2.2.5/i686/bin/ia64-unknown-linux-ld
OBJCOPY = /usr/local/sp_env/v2.2/i686/bin/ia64-unknown-linux-objcopy
endif
HOSTCC := gcc
#LD := ld
# Linker should relocate monitor to this address
MONITOR_BASE := 0xFC500000
# Bootloader should load monitor to this real address
LOAD_BASE    := 0x00100000
AFLAGS  += -D__ASSEMBLY__
CPPFLAGS  += -I$(BASEDIR)/include -I$(BASEDIR)/include/asm-ia64
CFLAGS  := -nostdinc -fno-builtin -fno-common -fno-strict-aliasing
#CFLAGS  += -O3		# -O3 over-inlines making debugging tough!
CFLAGS  += -O2		# but no optimization causes compile errors!
CFLAGS  += -iwithprefix include -Wall -DMONITOR_BASE=$(MONITOR_BASE)
CFLAGS  += -fomit-frame-pointer -I$(BASEDIR)/include -D__KERNEL__
CFLAGS  += -I$(BASEDIR)/include/asm-ia64
CFLAGS  += -Wno-pointer-arith -Wredundant-decls
CFLAGS  += -DIA64 -DXEN -DLINUX_2_6
CFLAGS	+= -ffixed-r13 -mfixed-range=f12-f15,f32-f127
CFLAGS	+= -w -g
#TARGET_CPU := i686
#CFLAGS += -march=$(TARGET_CPU)
#LDARCHFLAGS := --oformat elf32-i386 
LDFLAGS := -g
