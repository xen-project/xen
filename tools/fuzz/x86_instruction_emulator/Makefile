XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: x86-instruction-emulator-fuzzer-all
ifeq ($(CONFIG_X86_64),y)
x86-instruction-emulator-fuzzer-all: x86-insn-emulator.a x86-insn-emulator-fuzzer.o
else
x86-instruction-emulator-fuzzer-all:
endif

x86_emulate/x86_emulate.c x86_emulate/x86_emulate.h:
	[ -L x86_emulate ] || ln -sf $(XEN_ROOT)/xen/arch/x86/x86_emulate .

x86_emulate.c x86_emulate.h: %:
	[ -L $* ] || ln -sf $(XEN_ROOT)/tools/tests/x86_emulator/$*

CFLAGS += $(CFLAGS_xeninclude)

x86_emulate.o: x86_emulate.c x86_emulate.h x86_emulate/x86_emulate.c x86_emulate/x86_emulate.h

x86-insn-emulator.a: x86_emulate.o
	$(AR) rc $@ $^

x86-insn-emulator-fuzzer.o: x86-insn-emulator-fuzzer.c

# Common targets
.PHONY: all
all: x86-instruction-emulator-fuzzer-all

.PHONY: distclean
distclean: clean
	rm -f x86_emulate x86_emulate.c x86_emulate.h

.PHONY: clean
clean:
	rm -f *.a *.o
