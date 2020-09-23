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
SUBDIRS-y += ctrl
SUBDIRS-y += guest
SUBDIRS-y += hypfs
SUBDIRS-y += store
SUBDIRS-y += stat
SUBDIRS-$(CONFIG_Linux) += vchan
SUBDIRS-y += light
SUBDIRS-y += util

ifeq ($(CONFIG_RUMP),y)
SUBDIRS-y := toolcore
endif

all clean install distclean uninstall: %: subdirs-%
