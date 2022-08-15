XEN_ROOT = $(CURDIR)/../../..

LIB_SRCS-y = ext2fs-lib.c

FS = ext2fs-lib

FS_LIBDEPS = $(EXTFS_LIBS)

# Include configure output (config.h)
CFLAGS += -include $(XEN_ROOT)/tools/config.h

include $(XEN_ROOT)/tools/libfsimage/Rules.mk
