XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS := libs
SUBDIRS += xenstored

.NOTPARALLEL:
# targets here must be run in order, otherwise we can try
# to build programs before the libraries are done

.PHONY: all
all: subdirs-all

.PHONY: install
install: subdirs-install

.PHONY: uninstall
uninstall: subdirs-uninstall

.PHONY: clean
clean: subdirs-clean

.PHONY: distclean
distclean: subdirs-distclean

.PHONY: build-tools-oxenstored
build-tools-oxenstored:
	$(MAKE) -s -C libs/eventchn
	$(MAKE) -s -C libs/mmap
	$(MAKE) -s -C libs/xb
	$(MAKE) -s -C libs/xc
	$(MAKE) -s -C libs/xsd_glue
	$(MAKE) -C xenstored

.PHONY: format
format:
	git ls-files '*.ml' '*.mli' | xargs -n1 ocp-indent -i
