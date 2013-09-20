
XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test_x86_emulator

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$(TARGET)

.PHONY: blowfish.h
blowfish.h:
	rm -f blowfish.bin
	XEN_TARGET_ARCH=x86_32 make -f blowfish.mk all
	(echo "static unsigned int blowfish32_code[] = {"; \
	od -v -t x blowfish.bin | sed 's/^[0-9]* /0x/' | sed 's/ /, 0x/g' | sed 's/$$/,/';\
	echo "};") >$@
	rm -f blowfish.bin
ifeq ($(XEN_COMPILE_ARCH),x86_64)
	XEN_TARGET_ARCH=x86_64 make -f blowfish.mk all
	(echo "static unsigned int blowfish64_code[] = {"; \
	od -v -t x blowfish.bin | sed 's/^[0-9]* /0x/' | sed 's/ /, 0x/g' | sed 's/$$/,/';\
	echo "};") >>$@
	rm -f blowfish.bin
endif

$(TARGET): x86_emulate.o test_x86_emulator.o
	$(HOSTCC) -o $@ $^

.PHONY: clean
clean:
	rm -rf $(TARGET) *.o *~ core blowfish.h blowfish.bin x86_emulate

.PHONY: install
install:

x86_emulate/x86_emulate.c x86_emulate/x86_emulate.h:
	[ -L x86_emulate ] || ln -sf $(XEN_ROOT)/xen/arch/x86/x86_emulate .

HOSTCFLAGS += $(CFLAGS_xeninclude)

x86_emulate.o: x86_emulate.c x86_emulate/x86_emulate.c x86_emulate/x86_emulate.h
	$(HOSTCC) $(HOSTCFLAGS) -c -g -o $@ $<

test_x86_emulator.o: test_x86_emulator.c blowfish.h x86_emulate/x86_emulate.h
	$(HOSTCC) $(HOSTCFLAGS) -c -g -o $@ $<
