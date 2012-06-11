obj-bin-y += head.o

head.o: reloc.S

%.S: %.c
	$(MAKE) -f build32.mk $@

reloc.S: head.S
