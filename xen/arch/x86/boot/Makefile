obj-bin-y += head.o

DEFS_H_DEPS = $(abs_srctree)/$(src)/defs.h $(abs_srctree)/include/xen/stdbool.h

CMDLINE_DEPS = $(DEFS_H_DEPS) $(abs_srctree)/$(src)/video.h \
	       $(BASEDIR)/include/xen/kconfig.h \
	       $(BASEDIR)/include/generated/autoconf.h

RELOC_DEPS = $(DEFS_H_DEPS) \
	     $(BASEDIR)/include/generated/autoconf.h \
	     $(BASEDIR)/include/xen/kconfig.h \
	     $(BASEDIR)/include/xen/multiboot.h \
	     $(BASEDIR)/include/xen/multiboot2.h \
	     $(BASEDIR)/include/xen/const.h \
	     $(BASEDIR)/include/public/arch-x86/hvm/start_info.h

$(obj)/head.o: $(obj)/cmdline.S $(obj)/reloc.S

$(obj)/cmdline.S: $(src)/cmdline.c $(CMDLINE_DEPS) $(src)/build32.lds
	$(MAKE) -f $(abs_srctree)/$(src)/build32.mk -C $(obj) $(@F) CMDLINE_DEPS="$(CMDLINE_DEPS)"

$(obj)/reloc.S: $(src)/reloc.c $(RELOC_DEPS) $(src)/build32.lds
	$(MAKE) -f $(abs_srctree)/$(src)/build32.mk -C $(obj) $(@F) RELOC_DEPS="$(RELOC_DEPS)"

clean-files := cmdline.S reloc.S *.lnk *.bin
