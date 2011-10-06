XEN_ROOT = $(CURDIR)/../../..

LIB_SRCS-y = fsys_iso9660.c

FS = iso9660

.PHONY: all
all: fs-all

.PHONY: install
install: fs-install

fsys_iso9660.c: iso9660.h

include $(XEN_ROOT)/tools/libfsimage/Rules.mk
