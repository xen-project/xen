XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y := utils
SUBDIRS-$(FLASK_POLICY) += policy

.PHONY: all clean install distclean uninstall
all clean install distclean uninstall: %: subdirs-%

