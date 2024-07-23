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
	mkdir -p $@
	ln -sf $(XEN_ROOT)/xen/arch/x86/$@/*.[ch] $@/

x86_emulate/%.c: x86_emulate ;
x86_emulate/%.h: x86_emulate ;

%.c: $(XEN_ROOT)/tools/tests/x86_emulator/%.c FORCE
	ln -nsf $< $@
%.h: $(XEN_ROOT)/tools/tests/x86_emulator/%.h FORCE
	ln -nsf $< $@

CFLAGS += $(CFLAGS_xeninclude) -D__XEN_TOOLS__ -iquote .
cpuid.o: CFLAGS += -iquote $(XEN_ROOT)/xen/lib/x86

GCOV_FLAGS := --coverage
%-cov.o: %.c
	$(CC) -c $(CFLAGS) $(GCOV_FLAGS) $< -o $@

OBJS := fuzz-emul.o x86-emulate.o
OBJS += x86_emulate/0f01.o x86_emulate/0fae.o x86_emulate/0fc7.o
OBJS += x86_emulate/decode.o x86_emulate/fpu.o

WRAPPED = $(shell sed -n 's,^ *WRAP(\([[:alnum:]_]*\));,\1,p' x86-emulate.h)

private.h := x86-emulate.h x86_emulate/x86_emulate.h x86_emulate/private.h

x86-emulate.h: x86_emulate/x86_emulate.h
x86-emulate.o x86-emulate-cov.o: x86_emulate/x86_emulate.c $(private.h)
fuzz-emul.o fuzz-emul-cov.o wrappers.o: x86-emulate.h

$(filter x86_emulate/%.o,$(OBJS)): x86_emulate/%.o: x86_emulate/%.c $(private.h)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_$*.o) -c -o $@ $< $(APPEND_CFLAGS)

$(patsubst %.o,%-cov.o,$(filter x86_emulate/%.o,$(OBJS))): x86_emulate/%-cov.o: x86_emulate/%.c $(private.h)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_$*.o) $(GCOV_FLAGS) -c -o $@ $< $(APPEND_CFLAGS)

x86-insn-fuzzer.a: $(OBJS) cpuid.o
	$(AR) rc $@ $^

afl-harness: afl-harness.o $(OBJS) cpuid.o wrappers.o
	$(CC) $(CFLAGS) $(addprefix -Wl$(comma)--wrap=,$(WRAPPED)) $^ -o $@

afl-harness-cov: afl-harness-cov.o $(patsubst %.o,%-cov.o,$(OBJS)) cpuid.o wrappers.o
	$(CC) $(CFLAGS) $(GCOV_FLAGS) $(addprefix -Wl$(comma)--wrap=,$(WRAPPED)) $^ -o $@

libfuzzer-harness: $(OBJS) cpuid.o wrappers.o
	$(CC) $(CFLAGS) $(LIB_FUZZING_ENGINE) -fsanitize=fuzzer $(addprefix -Wl$(comma)--wrap=,$(WRAPPED)) $^ -o $@

# Common targets
.PHONY: all
all: x86-insn-fuzz-all

.PHONY: distclean
distclean: clean

.PHONY: clean
clean:
	rm -f *.a *.o $(DEPS_RM) *.gcda *.gcno *.gcov
	rm -f afl-harness afl-harness-cov libfuzzer-harness
	rm -rf x86_emulate x86-emulate.c x86-emulate.h wrappers.c cpuid.c

.PHONY: install
install: all

.PHONY: uninstall

.PHONY: afl
afl: afl-harness

.PHONY: afl-cov
afl-cov: afl-harness-cov

-include $(DEPS_INCLUDE)
