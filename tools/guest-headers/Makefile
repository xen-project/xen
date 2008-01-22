XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all:

.PHONY: check
check:

.PHONY: install

install:
	mkdir -p $(DESTDIR)$(INCLUDEDIR)/xen/sys
	$(INSTALL_DATA) $(XEN_ROOT)/tools/include/$(XEN_OS)/*.h $(DESTDIR)$(INCLUDEDIR)/xen/sys

.PHONY: clean
clean:
