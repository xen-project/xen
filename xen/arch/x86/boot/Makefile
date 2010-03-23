obj-y += head.o

head.o: reloc.S

BOOT_TRAMPOLINE := $(shell sed -n 's,^\#define[[:space:]]\+BOOT_TRAMPOLINE[[:space:]]\+,,p' $(BASEDIR)/include/asm-x86/config.h)
%.S: %.c
	RELOC=$(BOOT_TRAMPOLINE) XEN_BITSPERLONG=$(patsubst x86_%,%,$(TARGET_SUBARCH)) $(MAKE) -f build32.mk $@

reloc.S: $(BASEDIR)/include/asm-x86/config.h
