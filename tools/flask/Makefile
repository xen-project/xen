XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS :=
SUBDIRS += libflask
SUBDIRS += utils

.PHONY: all clean install
all clean install: %: subdirs-%

