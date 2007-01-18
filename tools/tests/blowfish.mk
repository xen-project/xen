
override XEN_TARGET_ARCH = x86_32
XEN_ROOT = ../..
CFLAGS :=
include $(XEN_ROOT)/tools/Rules.mk

# Disable PIE/SSP if GCC supports them. They can break us.
CFLAGS  += $(call cc-option,$(CC),-nopie,)
CFLAGS  += $(call cc-option,$(CC),-fno-stack-protector,)
CFLAGS  += $(call cc-option,$(CC),-fno-stack-protector-all,)

OBJCOPY  = objcopy
CFLAGS  += -fno-builtin -O2 -msoft-float
LDFLAGS  = -nostdlib -Wl,-N -Wl,-Ttext -Wl,0x100000

.PHONY: all
all: blowfish.bin

blowfish.bin: blowfish.c
	$(CC) $(CFLAGS) -c blowfish.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o blowfish.tmp blowfish.o
	$(OBJCOPY) -O binary blowfish.tmp blowfish.bin
	rm -f blowfish.tmp
