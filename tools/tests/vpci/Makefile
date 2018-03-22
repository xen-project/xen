XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test_vpci

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$(TARGET)

$(TARGET): vpci.c vpci.h list.h main.c emul.h
	$(HOSTCC) -g -o $@ vpci.c main.c

.PHONY: clean
clean:
	rm -rf $(TARGET) *.o *~ vpci.h vpci.c list.h

.PHONY: distclean
distclean: clean

.PHONY: install
install:

vpci.c: $(XEN_ROOT)/xen/drivers/vpci/vpci.c
	# Trick the compiler so it doesn't complain about missing symbols
	sed -e '/#include/d' \
	    -e '1s;^;#include "emul.h"\
	             vpci_register_init_t *const __start_vpci_array[1]\;\
	             vpci_register_init_t *const __end_vpci_array[1]\;\
	             ;' <$< >$@

list.h: $(XEN_ROOT)/xen/include/xen/list.h
vpci.h: $(XEN_ROOT)/xen/include/xen/vpci.h
list.h vpci.h:
	sed -e '/#include/d' <$< >$@
