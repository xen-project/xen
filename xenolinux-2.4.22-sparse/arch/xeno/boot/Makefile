#
# arch/xeno/boot/Makefile
#

image.gz: image
	gzip -f -9 < $< > $@

image: $(TOPDIR)/vmlinux
	# Guest OS header -- first 8 bytes are identifier 'XenoGues'.
	echo -e -n 'XenoGues' >$@ 
	# Guest OS header -- next 4 bytes are load address (0xC0000000).
	echo -e -n '\000\000\000\300' >>$@
	$(OBJCOPY) $< image.body
	# Guest OS header is immediately followed by raw OS image.
	# Start address must be at byte 0.
	cat image.body >>$@
	rm -f image.body

dep:

clean:
	rm -f image image.gz
