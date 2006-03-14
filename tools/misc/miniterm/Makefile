XEN_ROOT:=../../..
include $(XEN_ROOT)/tools/Rules.mk

INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

TARGET = miniterm

all: $(TARGET)

install: all
	[ -d $(DESTDIR)/usr/bin ] || $(INSTALL_DIR) $(DESTDIR)/usr/bin
	$(INSTALL_PROG) $(TARGET) $(DESTDIR)/usr/bin

clean:
	$(RM) *.o $(TARGET) *~

$(TARGET): $(TARGET).c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<
