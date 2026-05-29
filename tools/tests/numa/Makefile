XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGETS := test-numa

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
	$(RM) -- *.o $(TARGETS) $(DEPS_RM) numa.h

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

numa.h: $(XEN_ROOT)/xen/include/xen/numa.h
	sed -e '/^#[[:space:]]*include/d' <$< >$@

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(CFLAGS_xeninclude)

test-numa: test-numa.c numa.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(APPEND_CFLAGS)

-include $(DEPS_INCLUDE)
