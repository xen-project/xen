obj-bin-y += head.o

DEFS_H_DEPS = defs.h $(BASEDIR)/include/xen/stdbool.h

CMDLINE_DEPS = $(DEFS_H_DEPS) video.h \
	       $(BASEDIR)/include/xen/kconfig.h \
	       $(BASEDIR)/include/generated/autoconf.h

RELOC_DEPS = $(DEFS_H_DEPS) \
	     $(BASEDIR)/include/generated/autoconf.h \
	     $(BASEDIR)/include/xen/kconfig.h \
	     $(BASEDIR)/include/xen/multiboot.h \
	     $(BASEDIR)/include/xen/multiboot2.h \
	     $(BASEDIR)/include/xen/const.h \
	     $(BASEDIR)/include/public/arch-x86/hvm/start_info.h

head.o: cmdline.S reloc.S

cmdline.S: cmdline.c $(CMDLINE_DEPS) build32.lds
	$(MAKE) -f build32.mk $@ CMDLINE_DEPS="$(CMDLINE_DEPS)"

reloc.S: reloc.c $(RELOC_DEPS) build32.lds
	$(MAKE) -f build32.mk $@ RELOC_DEPS="$(RELOC_DEPS)"
