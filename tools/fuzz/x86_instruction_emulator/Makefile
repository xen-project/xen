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

x86-emulate.c x86-emulate.h wrappers.c: %:
	[ -L $* ] || ln -sf $(XEN_ROOT)/tools/tests/x86_emulator/$*

CFLAGS += $(CFLAGS_xeninclude) -D__XEN_TOOLS__ -I.

GCOV_FLAGS := --coverage
%-cov.o: %.c
	$(CC) -c $(CFLAGS) $(GCOV_FLAGS) $< -o $@

x86.h := asm/x86-vendors.h asm/x86-defns.h asm/msr-index.h
x86_emulate.h := x86-emulate.h x86_emulate/x86_emulate.h $(x86.h)

# x86-emulate.c will be implicit for both
x86-emulate.o x86-emulate-cov.o: x86_emulate/x86_emulate.c $(x86_emulate.h)

fuzz-emul.o fuzz-emulate-cov.o: $(x86_emulate.h)

x86-insn-fuzzer.a: fuzz-emul.o x86-emulate.o
	$(AR) rc $@ $^

afl-harness: afl-harness.o fuzz-emul.o x86-emulate.o wrappers.o
	$(CC) $(CFLAGS) $^ -o $@

afl-harness-cov: afl-harness-cov.o fuzz-emul-cov.o x86-emulate-cov.o wrappers.o
	$(CC) $(CFLAGS) $(GCOV_FLAGS) $^ -o $@

# Common targets
.PHONY: all
all: x86-insn-fuzz-all

.PHONY: distclean
distclean: clean
	rm -f x86_emulate x86-emulate.c x86-emulate.h asm

.PHONY: clean
clean:
	rm -f *.a *.o .*.d afl-harness afl-harness-cov *.gcda *.gcno *.gcov

.PHONY: install
install: all

.PHONY: uninstall

.PHONY: afl
afl: afl-harness

.PHONY: afl-cov
afl-cov: afl-harness-cov
