XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test-rangeset

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$<

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGET) $(DEPS_RM)

.PHONY: distclean
distclean: clean
	$(RM) -- *~

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) $(TARGET) $(DESTDIR)$(LIBEXEC_BIN)

.PHONY: uninstall
uninstall:
	$(RM) -- $(addprefix $(DESTDIR)$(LIBEXEC_BIN)/,$(TARGET))

list.h: $(XEN_ROOT)/xen/include/xen/list.h
rangeset.h: $(XEN_ROOT)/xen/include/xen/rangeset.h
list.h rangeset.h:
	sed -e '/#include/d' <$< >$@

rangeset.c: $(XEN_ROOT)/xen/common/rangeset.c list.h rangeset.h
	# Remove includes and add the test harness header
	sed -e '/#include/d' -e '1s/^/#include "harness.h"/' <$< >$@

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(APPEND_CFLAGS)
CFLAGS += $(CFLAGS_xeninclude)

LDFLAGS += $(APPEND_LDFLAGS)

test-rangeset: rangeset.o test-rangeset.o
	$(CC) $^ -o $@ $(LDFLAGS)
