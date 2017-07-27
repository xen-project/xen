XEN_ROOT = $(CURDIR)/../../..

LIB_SRCS-y = ext2fs-lib.c

FS = ext2fs-lib

FS_LIBDEPS = $(EXTFS_LIBS)

# Include configure output (config.h)
CFLAGS += -include $(XEN_ROOT)/tools/config.h

.PHONY: all
all: fs-all

.PHONY: install
install: fs-install

.PHONY: uninstall
uninstall: fs-uninstall

include $(XEN_ROOT)/tools/libfsimage/Rules.mk
