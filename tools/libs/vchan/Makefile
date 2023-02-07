XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += $(CFLAGS_libxenctrl)

LIBHEADER := libxenvchan.h

OBJS-y += init.o
OBJS-y += io.o

NO_HEADERS_CHK := y

include $(XEN_ROOT)/tools/libs/libs.mk
