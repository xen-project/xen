XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

OBJS-y += libxlu_cfg_y.o
OBJS-y += libxlu_cfg_l.o
OBJS-y += libxlu_cfg.o
OBJS-y += libxlu_disk_l.o
OBJS-y += libxlu_disk.o
OBJS-y += libxlu_vif.o
OBJS-y += libxlu_pci.o

CFLAGS += -Wno-format-zero-length -Wmissing-declarations \
	-Wno-declaration-after-statement -Wformat-nonliteral
CFLAGS += -I. $(CFLAGS_libxenctrl)

CFLAGS += $(PTHREAD_CFLAGS)
LDFLAGS += $(PTHREAD_LDFLAGS)

ifeq ($(FLEX),)
%.c %.h:: %.l
	$(warning Flex is needed to rebuild some libxl parsers and \
		  scanners, please install it and rerun configure)
endif

ifeq ($(BISON),)
%.c %.h:: %.y
	$(warning Bison is needed to rebuild some libxl parsers and \
		  scanners, please install it and rerun configure)
endif

AUTOINCS = libxlu_cfg_y.h libxlu_cfg_l.h libxlu_disk_l.h
AUTOSRCS = libxlu_cfg_y.c libxlu_cfg_l.c

LIBHEADER := libxlutil.h
PKG_CONFIG_NAME := Xlutil
PKG_CONFIG_DESC := The xl utility library for Xen hypervisor

NO_HEADERS_CHK := y

include $(XEN_ROOT)/tools/libs/libs.mk

$(OBJS-y) $(PIC_OBJS): $(AUTOINCS)

%.c %.h:: %.y
	@rm -f $*.[ch]
	$(BISON) --output=$*.c $<

%.c %.h:: %.l
	@rm -f $*.[ch]
	$(FLEX) --header-file=$*.h --outfile=$*.c $<

clean::
	$(RM) libxenutil.map
