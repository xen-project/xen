XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS := libs
SUBDIRS += xenstored

ifeq ($(CONFIG_TESTS),y)
SUBDIRS += test
endif

.NOTPARALLEL:
# targets here must be run in order, otherwise we can try
# to build programs before the libraries are done

.PHONY: all
all: subdirs-all

.PHONY: install
install: subdirs-install

.PHONY: clean
clean: subdirs-clean
