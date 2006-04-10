XEN_ROOT:=../../..
include $(XEN_ROOT)/tools/Rules.mk

INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

TARGET = miniterm

.PHONY: all
all: $(TARGET)

.PHONY: install
install: all
	[ -d $(DESTDIR)/usr/bin ] || $(INSTALL_DIR) $(DESTDIR)/usr/bin
	$(INSTALL_PROG) $(TARGET) $(DESTDIR)/usr/bin

.PHONY: clean
clean:
	$(RM) *.o $(TARGET) *~

$(TARGET): $(TARGET).c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<
