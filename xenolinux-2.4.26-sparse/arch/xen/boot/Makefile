#
# arch/xen/boot/Makefile
#

xenolinux.gz: xenolinux
	gzip -f -9 < $< > $@

xenolinux: $(TOPDIR)/vmlinux
	$(OBJCOPY) $< $@

dep:

clean:
	rm -f xenolinux*
