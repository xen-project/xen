#
# arch/xen/boot/Makefile
#

bzImage: $(TOPDIR)/vmlinux
	$(OBJCOPY) $< Image
	gzip -f -9 < Image > $@
	rm -f Image

dep:

clean:
	rm -f bzImage Image
