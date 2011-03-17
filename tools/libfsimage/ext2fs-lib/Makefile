XEN_ROOT = $(CURDIR)/../../..

LIB_SRCS-y = ext2fs-lib.c

FS = ext2fs-lib

FS_LIBDEPS = -lext2fs

.PHONY: all
all: fs-all

.PHONY: install
install: fs-install

include $(XEN_ROOT)/tools/libfsimage/Rules.mk
