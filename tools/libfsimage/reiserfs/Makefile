XEN_ROOT = $(CURDIR)/../../..

LIB_SRCS-y = fsys_reiserfs.c

FS = reiserfs

.PHONY: all
all: fs-all

.PHONY: install
install: fs-install

include $(XEN_ROOT)/tools/libfsimage/Rules.mk
