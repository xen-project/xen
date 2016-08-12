
XEN_ROOT = $(CURDIR)/../../..
CFLAGS =
include $(XEN_ROOT)/tools/Rules.mk

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))

CFLAGS += -fno-builtin -msoft-float $(BLOWFISH_CFLAGS)

.PHONY: all
all: blowfish.bin

blowfish.bin: blowfish.c
	$(CC) $(CFLAGS) -c blowfish.c
	$(LD) $(LDFLAGS_DIRECT) -N -Ttext 0x100000 -o blowfish.tmp blowfish.o
	$(OBJCOPY) -O binary blowfish.tmp blowfish.bin
	rm -f blowfish.tmp
