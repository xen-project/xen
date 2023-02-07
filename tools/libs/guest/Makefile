XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

include Makefile.common

xg_dom_bzimageloader.o xg_dom_bzimageloader.opic: CFLAGS += $(ZLIB_CFLAGS)

$(LIBELF_OBJS:.o=.opic): CFLAGS += -Wno-pointer-sign

LIBHEADER := xenguest.h

NO_HEADERS_CHK := y

include $(XEN_ROOT)/tools/libs/libs.mk

libxenguest.so.$(MAJOR).$(MINOR): LDLIBS += $(ZLIB_LIBS) -lz
