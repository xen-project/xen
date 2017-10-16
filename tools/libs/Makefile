XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += toolcore
SUBDIRS-y += toollog
SUBDIRS-y += evtchn
SUBDIRS-y += gnttab
SUBDIRS-y += call
SUBDIRS-y += foreignmemory
SUBDIRS-y += devicemodel

ifeq ($(CONFIG_RUMP),y)
SUBDIRS-y := toolcore
endif

all clean install distclean uninstall: %: subdirs-%
