XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGETS := test-pdx-mask

.PHONY: all
all: $(TARGETS)

.PHONY: run
run: $(TARGETS)
ifeq ($(CC),$(HOSTCC))
	set -e;             \
	for test in $? ; do \
		./$$test ;  \
	done
else
	$(warning HOSTCC != CC, will not run test)
endif

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGETS) $(DEPS_RM) pdx.h

.PHONY: distclean
distclean: clean
	$(RM) -- *~

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC)/tests
	$(INSTALL_PROG) $(TARGETS) $(DESTDIR)$(LIBEXEC)/tests

.PHONY: uninstall
uninstall:
	$(RM) -- $(patsubst %,$(DESTDIR)$(LIBEXEC)/tests/%,$(TARGETS))

pdx.h: $(XEN_ROOT)/xen/include/xen/pdx.h
	sed -E -e '/^#[[:space:]]*include/d' <$< >$@

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(APPEND_CFLAGS)
CFLAGS += $(CFLAGS_xeninclude)

test-pdx-mask: CFLAGS += -DCONFIG_PDX_MASK_COMPRESSION

test-pdx-%: test-pdx.c pdx.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_$*.o) -o $@ $< $(APPEND_CFLAGS)

-include $(DEPS_INCLUDE)
