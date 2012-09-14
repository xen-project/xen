XEN_ROOT = $(CURDIR)/../../..

LIB_SRCS-y = ext2fs-lib.c

FS = ext2fs-lib

FS_LIBDEPS = $(EXTFS_LIBS)

# Include configure output (config.h) to headers search path
CFLAGS += -I$(XEN_ROOT)/tools

.PHONY: all
all: fs-all

.PHONY: install
install: fs-install

include $(XEN_ROOT)/tools/libfsimage/Rules.mk
