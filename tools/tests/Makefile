XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += resource
SUBDIRS-$(CONFIG_X86) += cpu-policy
SUBDIRS-$(CONFIG_X86) += tsx
ifneq ($(clang),y)
SUBDIRS-$(CONFIG_X86) += x86_emulator
endif
SUBDIRS-y += xenstore
SUBDIRS-y += depriv
SUBDIRS-y += vpci
SUBDIRS-y += paging-mempool

.PHONY: all clean install distclean uninstall
all clean distclean install uninstall: %: subdirs-%
