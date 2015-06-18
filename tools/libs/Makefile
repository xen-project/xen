XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += toollog
SUBDIRS-y += evtchn
SUBDIRS-y += gnttab
SUBDIRS-y += call
SUBDIRS-y += foreignmemory

all clean install distclean: %: subdirs-%
