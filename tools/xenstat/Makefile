XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS :=
SUBDIRS += libxenstat
SUBDIRS += xentop

.PHONY: all install clean distclean

all install clean distclean: %: subdirs-%
