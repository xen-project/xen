XEN_ROOT:=../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET = miniterm

.PHONY: all
all: $(TARGET)

.PHONY: install
install: all
	[ -d $(DESTDIR)/usr/bin ] || $(INSTALL_DIR) $(DESTDIR)/usr/bin
	$(INSTALL_PROG) $(TARGET) $(DESTDIR)/usr/bin

.PHONY: install-recurse
	: No sense in installing miniterm on the Xen box.

.PHONY: clean
clean:
	$(RM) *.o $(TARGET) *~

$(TARGET): $(TARGET).c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<
