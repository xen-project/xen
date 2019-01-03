XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: test-cpu-policy

.PHONY: clean
clean:
	$(RM) -f -- *.o .*.d .*.d2 test-cpu-policy

.PHONY: distclean
distclean: clean
	$(RM) -f -- *~

.PHONY: install
install: all

.PHONY: uninstall

CFLAGS += -Werror $(CFLAGS_xeninclude) -D__XEN_TOOLS__ -O3
CFLAGS += $(APPEND_CFLAGS)

vpath %.c ../../../xen/lib/x86

test-cpu-policy: test-cpu-policy.o msr.o cpuid.o
	$(CC) $(CFLAGS) $^ -o $@

-include $(DEPS_INCLUDE)
