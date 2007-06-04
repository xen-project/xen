XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all:

.PHONY: check
check:

.PHONY: install install-Linux install-SunOS

install-Linux:
	mkdir -p $(DESTDIR)/usr/include/xen/linux
	$(INSTALL_DATA) $(XEN_ROOT)/tools/include/Linux/*.h $(DESTDIR)/usr/include/xen/linux

install-SunOS:

install: install-$(XEN_OS)

.PHONY: clean
clean:
