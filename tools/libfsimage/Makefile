XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y = common ufs reiserfs iso9660 fat zfs xfs
SUBDIRS-y += $(shell env CC="$(CC)" ./check-libext2fs)

.PHONY: all clean install
all clean install: %: subdirs-%

.PHONY: distclean
distclean: clean
