
override XEN_TARGET_ARCH = x86_32
XEN_ROOT = ../..
CFLAGS =
include $(XEN_ROOT)/tools/Rules.mk

# Disable PIE/SSP if GCC supports them. They can break us.
$(call cc-option-add,CFLAGS,CC,-nopie)
$(call cc-option-add,CFLAGS,CC,-fno-stack-protector)
$(call cc-option-add,CFLAGS,CC,-fno-stack-protector-all)

CFLAGS += -fno-builtin -msoft-float

.PHONY: all
all: blowfish.bin

blowfish.bin: blowfish.c
	$(CC) $(CFLAGS) -c blowfish.c
	$(LD) $(LDFLAGS_DIRECT) -N -Ttext 0x100000 -o blowfish.tmp blowfish.o
	$(OBJCOPY) -O binary blowfish.tmp blowfish.bin
	rm -f blowfish.tmp
