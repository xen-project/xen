#
# arch/xeno/boot/Makefile
#

xenolinux.gz: xenolinux
	gzip -f -9 < $< > $@

xenolinux: $(TOPDIR)/vmlinux
	# Guest OS header -- first 8 bytes are identifier 'XenGuest'.
	echo -e -n 'XenGuest' >$@ 
	# Guest OS header -- next 4 bytes are load address (0xC0000000).
	echo -e -n '\000\000\000\300' >>$@
	$(OBJCOPY) $< xenolinux.body
	# Guest OS header is immediately followed by raw OS image.
	# Start address must be at byte 0.
	cat xenolinux.body >>$@
	rm -f xenolinux.body

dep:

clean:
	rm -f xenolinux xenolinux.gz