obj-y += head.o

head.o: reloc.S

# NB. BOOT_TRAMPOLINE == 0x8c000
%.S: %.c
	RELOC=0x8c000 $(MAKE) -f build32.mk $@
