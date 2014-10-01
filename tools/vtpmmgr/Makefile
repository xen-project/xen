XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

all:
	@true

install:
	$(INSTALL_DIR) "$(DESTDIR)$(LIBEXEC_BIN)"
	$(INSTALL_DATA) calc.pl "$(DESTDIR)$(LIBEXEC_BIN)"
	$(INSTALL_DATA) manage-vtpmmgr.pl "$(DESTDIR)$(LIBEXEC_BIN)"

clean:
	@true

.PHONY: all install clean
