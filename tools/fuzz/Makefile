XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += libelf
SUBDIRS-y += x86_instruction_emulator

SUBDIRS-$(CONFIG_X86_64) += cpu-policy

.PHONY: all clean distclean install uninstall
all clean distclean install uninstall: %: subdirs-%
