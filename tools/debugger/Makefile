XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y := gdbsx
SUBDIRS-y += kdd

.PHONY: all clean install distclean uninstall
all clean install distclean uninstall: %: subdirs-%
