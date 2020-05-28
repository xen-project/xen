XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y = xenlight

.PHONY: build all
all build: subdirs-all

.PHONY: install
install: subdirs-install

.PHONY: uninstall
uninstall: subdirs-uninstall

.PHONY: clean
clean: subdirs-clean
	$(RM) -r src pkg

.PHONY: distclean
distclean: clean
