
XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test_x86_emulator

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$(TARGET)

TESTCASES := blowfish

blowfish-cflags := ""
blowfish-cflags-x86_32 := "-mno-accumulate-outgoing-args -Dstatic="

$(addsuffix .h,$(TESTCASES)): %.h: %.c testcase.mk Makefile
	rm -f $@.new $*.bin
	$(foreach arch,$(filter-out $(XEN_COMPILE_ARCH),x86_32) $(XEN_COMPILE_ARCH), \
	    for cflags in $($*-cflags) $($*-cflags-$(arch)); do \
		$(MAKE) -f testcase.mk TESTCASE=$* XEN_TARGET_ARCH=$(arch) $*-cflags="$$cflags" all; \
		flavor=$$(echo $${cflags} | sed -e 's, .*,,' -e 'y,-=,__,') ; \
		(echo "static const unsigned int $*_$(arch)$${flavor}[] = {"; \
		 od -v -t x $*.bin | sed -e 's/^[0-9]* /0x/' -e 's/ /, 0x/g' -e 's/$$/,/'; \
		 echo "};") >>$@.new; \
		rm -f $*.bin; \
	    done; \
	)
	mv $@.new $@

$(TARGET): x86_emulate.o test_x86_emulator.o
	$(HOSTCC) -o $@ $^

.PHONY: clean
clean:
	rm -rf $(TARGET) *.o *~ core $(addsuffix .h,$(TESTCASES)) *.bin x86_emulate asm

.PHONY: distclean
distclean: clean

.PHONY: install
install:

x86_emulate:
	[ -L $@ ] || ln -sf $(XEN_ROOT)/xen/arch/x86/$@

x86_emulate/%: x86_emulate ;

asm:
	[ -L $@ ] || ln -sf $(XEN_ROOT)/xen/include/asm-x86 $@

asm/%: asm ;

HOSTCFLAGS += $(CFLAGS_xeninclude) -I.

x86.h := asm/x86-vendors.h asm/x86-defns.h asm/msr-index.h
x86_emulate.h := x86_emulate.h x86_emulate/x86_emulate.h $(x86.h)

x86_emulate.o: x86_emulate.c x86_emulate/x86_emulate.c $(x86_emulate.h)
	$(HOSTCC) $(HOSTCFLAGS) -D__XEN_TOOLS__ -c -g -o $@ $<

test_x86_emulator.o: test_x86_emulator.c $(addsuffix .h,$(TESTCASES)) $(x86_emulate.h)
	$(HOSTCC) $(HOSTCFLAGS) -c -g -o $@ $<
