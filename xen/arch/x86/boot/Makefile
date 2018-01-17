obj-bin-y += head.o

DEFS_H_DEPS = defs.h $(BASEDIR)/include/xen/stdbool.h

CMDLINE_DEPS = $(DEFS_H_DEPS) video.h

RELOC_DEPS = $(DEFS_H_DEPS) $(BASEDIR)/include/xen/multiboot.h \
	     $(BASEDIR)/include/xen/multiboot2.h \
	     $(BASEDIR)/include/public/arch-x86/hvm/start_info.h

head.o: cmdline.S reloc.S

cmdline.S: cmdline.c $(CMDLINE_DEPS)
	$(MAKE) -f build32.mk $@ CMDLINE_DEPS="$(CMDLINE_DEPS)"

reloc.S: reloc.c $(RELOC_DEPS)
	$(MAKE) -f build32.mk $@ RELOC_DEPS="$(RELOC_DEPS)"
