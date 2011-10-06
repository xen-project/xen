XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SCRIPTS = remus

.PHONY: all
all: subdirs-all

.PHONY: install
install: subdirs-install
	$(INSTALL_DIR) $(DESTDIR)$(BINDIR)
	$(INSTALL_PYTHON_PROG) $(SCRIPTS) $(DESTDIR)$(BINDIR)

.PHONY: clean
clean: subdirs-clean
