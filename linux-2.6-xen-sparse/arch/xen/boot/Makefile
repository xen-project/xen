
OBJCOPYFLAGS := -g --strip-unneeded

vmlinuz: vmlinux-stripped FORCE
	$(call if_changed,gzip)

vmlinux-stripped: vmlinux FORCE
	$(call if_changed,objcopy)

bzImage: vmlinuz
	$(Q)$(LN) -sf ../../../vmlinuz $(srctree)/arch/xen/boot/bzImage
