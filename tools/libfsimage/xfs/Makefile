XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/libfsimage/Rules.mk

LIB_SRCS-y = fsys_xfs.c

FS = xfs

.PHONY: all
all: fs-all

.PHONY: install
install: fs-install
