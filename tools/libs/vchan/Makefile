XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += $(CFLAGS_libxenctrl)

LIBHEADER := libxenvchan.h

SRCS-y += init.c
SRCS-y += io.c

NO_HEADERS_CHK := y

include $(XEN_ROOT)/tools/libs/libs.mk

$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_libxenvchan)/include
$(PKG_CONFIG_LOCAL): PKG_CONFIG_CFLAGS_LOCAL = $(CFLAGS_xeninclude)

clean: cleanlocal

.PHONY: cleanlocal
cleanlocal:
	rm -f libxenvchan.map
