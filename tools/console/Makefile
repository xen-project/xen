XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y := daemon client

.PHONY: all clean install distclean uninstall
all clean install distclean uninstall: %: subdirs-%
