XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: x86-insn-fuzz-all
ifeq ($(CONFIG_X86_64),y)
x86-insn-fuzz-all: x86-insn-fuzzer.a fuzz-emul.o afl
else
x86-insn-fuzz-all:
endif

CFLAGS += $(CFLAGS_xeninclude) -D__XEN_TOOLS__

# Add the core emulator to the build
vpath x86_emulate/%.c $(XEN_ROOT)/xen/arch/x86
vpath x86_emulate/%.h $(XEN_ROOT)/xen/arch/x86
CFLAGS += -iquote $(XEN_ROOT)/xen/arch/x86

# Add the emulator test harness to the build
vpath %.c ../../tests/x86_emulator
vpath %.h ../../tests/x86_emulator
CFLAGS += -iquote ../../tests/x86_emulator

# Add libx86 to the build
vpath %.c $(XEN_ROOT)/xen/lib/x86

x86_emulate:
	mkdir -p $@

GCOV_FLAGS := --coverage
%-cov.o: %.c
	$(CC) -c $(CFLAGS) $(GCOV_FLAGS) $< -o $@

OBJS := fuzz-emul.o x86-emulate.o
OBJS += x86_emulate/0f01.o x86_emulate/0fae.o x86_emulate/0fc7.o
OBJS += x86_emulate/decode.o x86_emulate/fpu.o

WRAPPED = $(shell sed -n 's,^ *WRAP(\([[:alnum:]_]*\));,\1,p' \
                      ../../tests/x86_emulator/x86-emulate.h)

$(filter x86_emulate/%.o,$(OBJS)): x86_emulate/%.o: x86_emulate/%.c x86_emulate
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_$*.o) -c -o $@ $< $(APPEND_CFLAGS)

$(patsubst %.o,%-cov.o,$(filter x86_emulate/%.o,$(OBJS))): x86_emulate/%-cov.o: x86_emulate/%.c x86_emulate
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
	rm -rf x86_emulate

.PHONY: install
install: all

.PHONY: uninstall

.PHONY: afl
afl: afl-harness

.PHONY: afl-cov
afl-cov: afl-harness-cov

-include $(DEPS_INCLUDE)
