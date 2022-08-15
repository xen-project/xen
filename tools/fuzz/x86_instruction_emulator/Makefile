XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: x86-insn-fuzz-all
ifeq ($(CONFIG_X86_64),y)
x86-insn-fuzz-all: x86-insn-fuzzer.a fuzz-emul.o afl
else
x86-insn-fuzz-all:
endif

# Add libx86 to the build
%.c: $(XEN_ROOT)/xen/lib/x86/%.c FORCE
	ln -nsf $< $@

x86_emulate: FORCE
	ln -nsf $(XEN_ROOT)/xen/arch/x86/$@

x86_emulate/%: x86_emulate ;

%.c: $(XEN_ROOT)/tools/tests/x86_emulator/%.c FORCE
	ln -nsf $< $@
%.h: $(XEN_ROOT)/tools/tests/x86_emulator/%.h FORCE
	ln -nsf $< $@

CFLAGS += $(CFLAGS_xeninclude) -D__XEN_TOOLS__ -iquote .
cpuid.o: CFLAGS += -iquote $(XEN_ROOT)/xen/lib/x86

GCOV_FLAGS := --coverage
%-cov.o: %.c
	$(CC) -c $(CFLAGS) $(GCOV_FLAGS) $< -o $@

x86-emulate.h: x86_emulate/x86_emulate.h
x86-emulate.o x86-emulate-cov.o: x86-emulate.h x86_emulate/x86_emulate.c
fuzz-emul.o fuzz-emul-cov.o wrappers.o: x86-emulate.h

x86-insn-fuzzer.a: fuzz-emul.o x86-emulate.o cpuid.o
	$(AR) rc $@ $^

afl-harness: afl-harness.o fuzz-emul.o x86-emulate.o cpuid.o wrappers.o
	$(CC) $(CFLAGS) $^ -o $@

afl-harness-cov: afl-harness-cov.o fuzz-emul-cov.o x86-emulate-cov.o cpuid.o wrappers.o
	$(CC) $(CFLAGS) $(GCOV_FLAGS) $^ -o $@

# Common targets
.PHONY: all
all: x86-insn-fuzz-all

.PHONY: distclean
distclean: clean
	rm -f x86_emulate x86-emulate.c x86-emulate.h wrappers.c cpuid.c

.PHONY: clean
clean:
	rm -f *.a *.o $(DEPS_RM) afl-harness afl-harness-cov *.gcda *.gcno *.gcov

.PHONY: install
install: all

.PHONY: uninstall

.PHONY: afl
afl: afl-harness

.PHONY: afl-cov
afl-cov: afl-harness-cov

-include $(DEPS_INCLUDE)
