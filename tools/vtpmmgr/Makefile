XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

all:
	@true

install:
	$(INSTALL_DIR) "$(DESTDIR)$(LIBEXEC)"
	$(INSTALL_DATA) calc.pl "$(DESTDIR)$(LIBEXEC)"
	$(INSTALL_DATA) manage-vtpmmgr.pl "$(DESTDIR)$(LIBEXEC)"

clean:
	@true

.PHONY: all install clean
