XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all:

.PHONY: check
check:

.PHONY: install

install:
	mkdir -p $(DESTDIR)/usr/include/xen/sys
	$(INSTALL_DATA) $(XEN_ROOT)/tools/include/$(XEN_OS)/*.h $(DESTDIR)/usr/include/xen/sys

.PHONY: clean
clean:
