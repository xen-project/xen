XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += toollog
SUBDIRS-y += evtchn

all clean install distclean: %: subdirs-%
