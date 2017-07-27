XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y := common
SUBDIRS-$(CONFIG_NetBSD) += NetBSD
SUBDIRS-$(CONFIG_Linux) += Linux
SUBDIRS-$(CONFIG_FreeBSD) += FreeBSD

.PHONY: all clean install distclean uninstall
all clean install distclean uninstall: %: subdirs-%
