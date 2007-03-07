XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

linuxsparsetree = $(XEN_ROOT)/linux-2.6-xen-sparse

.PHONY: all
all:

.PHONY: check
check:

.PHONY: install install-Linux install-SunOS

install-Linux:
	mkdir -p $(DESTDIR)/usr/include/xen/linux
	$(INSTALL_DATA) $(linuxsparsetree)/include/xen/public/*.h $(DESTDIR)/usr/include/xen/linux

install-SunOS:

install: install-$(XEN_OS)

.PHONY: clean
clean:
