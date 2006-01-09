
XEN_ROOT=../..
linuxsparsetree = $(XEN_ROOT)/linux-2.6-xen-sparse

check:

install:
	mkdir -p $(DESTDIR)/usr/include/xen/linux
	install -m0644 $(linuxsparsetree)/include/asm-xen/linux-public/*.h $(DESTDIR)/usr/include/xen/linux

clean:
