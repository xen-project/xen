XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += lib
SUBDIRS-y += drivers

.PHONY: all clean install
all clean install: %: subdirs-%

install:
	$(INSTALL_DIR) $(DESTDIR)$(DOCDIR)
	$(INSTALL_DATA) README $(DESTDIR)$(DOCDIR)/README.blktap
