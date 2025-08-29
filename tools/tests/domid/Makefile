# SPDX-License-Identifier: GPL-2.0-only
#
# Unit tests for domain ID allocator.
#
# Copyright 2025 Ford Motor Company

XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TESTS := test-domid

define list-c-headers
$(shell sed -n -E \
    's/^[ \t]*# *include[ \t]*[<"]([^">]+)[">].*/\1/p' $(1) 2>/dev/null)
endef

# NB: $1 cannot be a list
define emit-harness-nested-rule
$(1): $(CURDIR)/harness.h
	mkdir -p $$(@D);
	ln -sf $$< $$@;

endef

define emit-harness-rules
$(foreach x,$(2),$(call emit-harness-nested-rule,$(CURDIR)/generated/$(x)))
$(1:.c=.o): $(addprefix $(CURDIR)/generated/,$(2))
endef

define emit-harness-deps
$(if $(strip $(2)),$(call emit-harness-rules,$1,$2),)
endef

define vpath-with-harness-deps
vpath $(1) $(2)
$(call emit-harness-deps,$(1),$(call list-c-headers,$(2)$(1)))
endef

.PHONY: all
all: $(TESTS)

.PHONY: run
run: $(TESTS)
	set -e; $(foreach t,$(TESTS),./$(t);)

.PHONY: clean
clean:
	$(RM) -r generated
	$(RM) -- *.o $(TESTS) $(DEPS_RM)

.PHONY: distclean
distclean: clean
	$(RM) -- *~

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC)/tests
	$(INSTALL_PROG) test-domid $(DESTDIR)$(LIBEXEC)/tests

.PHONY: uninstall
uninstall:
	$(RM) -- $(DESTDIR)$(LIBEXEC)/tests/test-domid

CFLAGS += -D__XEN_TOOLS__
# find-next-bit.c
CFLAGS += '-DEXPORT_SYMBOL(x)=' \
          -Dfind_first_bit \
          -Dfind_first_zero_bit \
          -Dfind_next_bit \
          -Dfind_next_bit_le \
          -Dfind_next_zero_bit_le
CFLAGS += $(APPEND_CFLAGS)
CFLAGS += $(CFLAGS_xeninclude)
CFLAGS += -I./generated/

LDFLAGS += $(APPEND_LDFLAGS)

vpath find-next-bit.c $(XEN_ROOT)/xen/lib/

# Point to the hypervisor code and generate test harness dependencies
# on the fly, making it possible to compile parts of the hypervisor
# within a mocked environment.
$(eval $(call vpath-with-harness-deps,domid.c,$(XEN_ROOT)/xen/common/))

test-domid: domid.o find-next-bit.o test-domid.o
	$(CC) $^ -o $@ $(LDFLAGS)

-include $(DEPS_INCLUDE)
