
XEN_ROOT=../..
linuxsparsetree = $(XEN_ROOT)/linux-2.6-xen-sparse

.PHONY: all
all:

.PHONY: check
check:

.PHONY: install
install:
	mkdir -p $(DESTDIR)/usr/include/xen/linux
	install -m0644 $(linuxsparsetree)/include/xen/public/*.h $(DESTDIR)/usr/include/xen/linux

.PHONY: clean
clean:
