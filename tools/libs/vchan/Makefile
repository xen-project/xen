XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += $(CFLAGS_libxenctrl)

LIBHEADER := libxenvchan.h

SRCS-y += init.c
SRCS-y += io.c

NO_HEADERS_CHK := y

include $(XEN_ROOT)/tools/libs/libs.mk

clean: cleanlocal

.PHONY: cleanlocal
cleanlocal:
	rm -f libxenvchan.map
