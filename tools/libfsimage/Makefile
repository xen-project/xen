XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y = common ufs reiserfs iso9660 fat
SUBDIRS-y += $(shell env CC="$(CC)" ./check-libext2fs)

.PHONE: all clean install
all clean install: %: subdirs-%

distclean: clean
