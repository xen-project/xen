XEN_ROOT:=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET = miniterm

.PHONY: all
all: $(TARGET)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(BINDIR)
	$(INSTALL_PROG) $(TARGET) $(DESTDIR)$(BINDIR)

.PHONY: install-recurse
	: No sense in installing miniterm on the Xen box.

.PHONY: clean
clean:
	$(RM) *.o $(TARGET) *~

$(TARGET): $(TARGET).c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<
