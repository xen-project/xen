XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGETS :=

# For brevity, these tests make extensive use of designated initialisers in
# anonymous unions, but GCCs older than 4.6 can't cope.  Ignore the test in
# this case.
ifneq ($(gcc)$(call cc-ver,$(CC),lt,0x040600),yy)
TARGETS += test-cpu-policy
else
$(warning Test harness not built, use newer compiler than "$(CC)" (version $(shell $(CC) -dumpversion)))
endif

.PHONY: all
all: $(TARGETS)

.PHONY: run
run: $(TARGETS)
	./$<

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGETS) $(DEPS_RM)

.PHONY: distclean
distclean: clean
	$(RM) -- *~

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(if $(TARGETS),$(INSTALL_PROG) $(TARGETS) $(DESTDIR)$(LIBEXEC_BIN))

.PHONY: uninstall
uninstall:
	$(RM) -- $(addprefix $(DESTDIR)$(LIBEXEC_BIN)/,$(TARGETS))

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(CFLAGS_xeninclude)
CFLAGS += $(APPEND_CFLAGS)

LDFLAGS += $(APPEND_LDFLAGS)

vpath %.c ../../../xen/lib/x86

%.o: Makefile

test-cpu-policy: test-cpu-policy.o msr.o cpuid.o policy.o
	$(CC) $^ -o $@ $(LDFLAGS)

-include $(DEPS_INCLUDE)
