XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += toollog
SUBDIRS-y += evtchn
SUBDIRS-y += gnttab

all clean install distclean: %: subdirs-%
