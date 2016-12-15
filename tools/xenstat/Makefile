XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS :=
SUBDIRS += libxenstat

# This doesn't cross-compile (cross-compile environments rarely have curses)
ifeq ($(XEN_COMPILE_ARCH),$(XEN_TARGET_ARCH))
SUBDIRS += xentop
endif

.PHONY: all install clean distclean

all install clean distclean: %: subdirs-%
