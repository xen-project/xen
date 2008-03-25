XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS :=
SUBDIRS += libflask
SUBDIRS += loadpolicy

.PHONY: all clean install
all clean install: %: subdirs-%

