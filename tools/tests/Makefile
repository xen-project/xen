XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += $(CFLAGS_libxenctrl)
LDLIBS += $(LDLIBS_libxenctrl)

SUBDIRS-y :=
SUBDIRS-y += mce-test
SUBDIRS-y += mem-sharing
ifeq ($(XEN_TARGET_ARCH),__fixme__)
SUBDIRS-y += regression
endif
SUBDIRS-y += x86_emulator
ifneq ($(XEN_TARGET_ARCH),x86_32)
SUBDIRS-y += xen-access
endif

.PHONY: all clean install distclean
all clean distclean: %: subdirs-%

install:
