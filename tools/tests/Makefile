
XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test_x86_emulator

HOSTCFLAGS += -D__TEST_HARNESS__

.PHONY: all
all: $(TARGET)

$(TARGET): x86_emulate.o test_x86_emulator.o
	$(HOSTCC) -o $@ $^

.PHONY: clean
clean:
	rm -rf $(TARGET) *.o *~ core

.PHONY: install
install:

x86_emulate.o: $(XEN_ROOT)/xen/arch/x86/x86_emulate.c
	$(HOSTCC) $(HOSTCFLAGS) -I$(XEN_ROOT)/xen/include -c -o $@ $<

%.o: %.c
	$(HOSTCC) $(HOSTCFLAGS) -I$(XEN_ROOT)/xen/include -c -o $@ $<
