XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: x86-insn-fuzz-all
ifeq ($(CONFIG_X86_64),y)
x86-insn-fuzz-all: x86-insn-fuzzer.a fuzz-emul.o afl
else
x86-insn-fuzz-all:
endif

x86_emulate:
	[ -L $@ ] || ln -sf $(XEN_ROOT)/xen/arch/x86/$@

x86_emulate/%: x86_emulate ;

asm:
	[ -L $@ ] || ln -sf $(XEN_ROOT)/xen/include/asm-x86 $@

asm/%: asm ;

x86_emulate.c x86_emulate.h: %:
	[ -L $* ] || ln -sf $(XEN_ROOT)/tools/tests/x86_emulator/$*

CFLAGS += $(CFLAGS_xeninclude) -D__XEN_TOOLS__ -I.

x86.h := asm/x86-vendors.h asm/x86-defns.h asm/msr-index.h
x86_emulate.h := x86_emulate.h x86_emulate/x86_emulate.h $(x86.h)

x86_emulate.o: x86_emulate.c x86_emulate/x86_emulate.c $(x86_emulate.h)

fuzz-emul.o: $(x86_emulate.h)

x86-insn-fuzzer.a: fuzz-emul.o x86_emulate.o
	$(AR) rc $@ $^

afl-harness: afl-harness.o fuzz-emul.o x86_emulate.o
	$(CC) $(CFLAGS) $^ -o $@

# Common targets
.PHONY: all
all: x86-insn-fuzz-all

.PHONY: distclean
distclean: clean
	rm -f x86_emulate x86_emulate.c x86_emulate.h asm

.PHONY: clean
clean:
	rm -f *.a *.o .*.d afl-harness

.PHONY: install
install: all

.PHONY: afl
afl: afl-harness
