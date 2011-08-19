obj-bin-y += head.o

head.o: reloc.S

BOOT_TRAMPOLINE := $(shell sed -n 's,^\#define[[:space:]]\{1\,\}BOOT_TRAMPOLINE[[:space:]]\{1\,\},,p' head.S)
%.S: %.c
	RELOC=$(BOOT_TRAMPOLINE) $(MAKE) -f build32.mk $@

reloc.S: head.S
