XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += domid
SUBDIRS-y += paging-mempool
SUBDIRS-y += pdx
SUBDIRS-y += rangeset
SUBDIRS-y += resource
SUBDIRS-y += vpci
SUBDIRS-y += xenstore

SUBDIRS-$(CONFIG_X86) += cpu-policy
SUBDIRS-$(CONFIG_X86) += tsx
ifneq ($(clang),y)
SUBDIRS-$(CONFIG_X86) += x86_emulator
endif

.PHONY: all clean install distclean uninstall
all clean distclean install uninstall: %: subdirs-%
