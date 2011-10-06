XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y := common
SUBDIRS-$(CONFIG_NetBSD) += NetBSD
SUBDIRS-$(CONFIG_Linux) += Linux

.PHONY: all clean install
all clean install: %: subdirs-%
