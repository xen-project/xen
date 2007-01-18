
XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test_x86_emulator

.PHONY: all
all: $(TARGET)

.PHONY: blowfish.bin
blowfish.bin:
	make -f blowfish.mk all

blowfish.h: blowfish.bin
	(echo "static unsigned int blowfish_code[] = {"; \
	od -v -t x $< | sed 's/^[0-9]* /0x/' | sed 's/ /, 0x/g' | sed 's/$$/,/';\
	echo "};") >$@

$(TARGET): x86_emulate.o test_x86_emulator.o
	$(HOSTCC) -o $@ $^

.PHONY: clean
clean:
	rm -rf $(TARGET) *.o *~ core blowfish.h blowfish.bin

.PHONY: install
install:

x86_emulate.o: $(XEN_ROOT)/xen/arch/x86/x86_emulate.c
	$(HOSTCC) $(HOSTCFLAGS) -I$(XEN_ROOT)/xen/include -c -o $@ $<

test_x86_emulator.o: test_x86_emulator.c blowfish.h
	$(HOSTCC) $(HOSTCFLAGS) -I$(XEN_ROOT)/xen/include -c -o $@ $<
