XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += $(CFLAGS_libxenctrl)
LDLIBS += $(LDLIBS_libxenctrl)

SUBDIRS-y :=
SUBDIRS-$(CONFIG_X86) += mce-test
SUBDIRS-y += mem-sharing
ifeq ($(XEN_TARGET_ARCH),__fixme__)
SUBDIRS-y += regression
endif
SUBDIRS-$(CONFIG_X86) += x86_emulator
SUBDIRS-y += xen-access

.PHONY: all clean install distclean
all clean distclean: %: subdirs-%

install:
