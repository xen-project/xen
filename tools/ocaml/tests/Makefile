XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += bindings

.PHONY: all clean install distclean uninstall
all clean distclean install uninstall: %: subdirs-%
