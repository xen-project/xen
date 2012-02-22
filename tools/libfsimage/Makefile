XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y = common ufs reiserfs iso9660 fat zfs
SUBDIRS-$(CONFIG_X86) += xfs
ifeq ($(CONFIG_EXT2FS), y)
    SUBDIRS-y += ext2fs-lib
else
    SUBDIRS-y += ext2fs
endif

.PHONY: all clean install
all clean install: %: subdirs-%

.PHONY: distclean
distclean: clean
