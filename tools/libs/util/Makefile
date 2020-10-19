XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

SRCS-y += libxlu_cfg_y.c
SRCS-y += libxlu_cfg_l.c
SRCS-y += libxlu_cfg.c
SRCS-y += libxlu_disk_l.c
SRCS-y += libxlu_disk.c
SRCS-y += libxlu_vif.c
SRCS-y += libxlu_pci.c

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

$(LIB_OBJS) $(PIC_OBJS): $(AUTOINCS) _paths.h

%.c %.h:: %.y
	@rm -f $*.[ch]
	$(BISON) --output=$*.c $<

%.c %.h:: %.l
	@rm -f $*.[ch]
	$(FLEX) --header-file=$*.h --outfile=$*.c $<

genpath-target = $(call buildmakevars2header,_paths.h)
$(eval $(genpath-target))

clean: cleanlocal

.PHONY: cleanlocal
cleanlocal:
	$(RM) -f _*.h
	$(RM) -f libxlutil.map
