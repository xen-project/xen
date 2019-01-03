XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: afl-policy-fuzzer

.PHONY: clean
clean:
	$(RM) -f -- *.o .*.d .*.d2 afl-policy-fuzzer

.PHONY: distclean
distclean: clean
	$(RM) -f -- *~

.PHONY: install
install: all

.PHONY: uninstall

CFLAGS += -Werror $(CFLAGS_xeninclude) -D__XEN_TOOLS__
CFLAGS += $(APPEND_CFLAGS) -Og

vpath %.c ../../../xen/lib/x86

afl-policy-fuzzer: afl-policy-fuzzer.o msr.o cpuid.o
	$(CC) $(CFLAGS) $^ -o $@

-include $(DEPS_INCLUDE)
