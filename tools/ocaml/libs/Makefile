XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS= \
	mmap \
	xentoollog \
	xc eventchn \
	xb xs xl

.PHONY: all
all: subdirs-all

.PHONY: install
install: subdirs-install

.PHONY: clean
clean: subdirs-clean
