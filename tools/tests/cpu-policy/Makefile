XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET-y := test-cpu-policy

# For brevity, these tests make extensive use of designated initialisers in
# anonymous unions, but GCCs older than 4.6 can't cope.  Ignore the test in
# this case.
ifneq ($(clang),y)
TARGET-$(call cc-ver,$(CC),lt,0x040600) :=
endif

ifeq ($(TARGET-y),)
$(warning Test harness not built, use newer compiler than "$(CC)" (version $(shell $(CC) -dumpversion)))
endif

.PHONY: all
all: $(TARGET-y)

.PHONY: run
run: $(TARGET-y)
	./$(TARGET-y)

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

test-cpu-policy: test-cpu-policy.o msr.o cpuid.o policy.o
	$(CC) $(CFLAGS) $^ -o $@

-include $(DEPS_INCLUDE)
