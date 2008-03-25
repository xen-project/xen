XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += lib
SUBDIRS-y += drivers

.PHONY: all clean install
all clean install: %: subdirs-%

