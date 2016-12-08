XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += libelf
SUBDIRS-y += x86_instruction_emulator

.PHONY: all clean distclean
all clean distclean: %: subdirs-%

install:
