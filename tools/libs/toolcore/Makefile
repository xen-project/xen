XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR	= 1
MINOR	= 0
AUTOINCS := $(XEN_INCLUDE)/_xentoolcore_list.h

LIBHEADER := xentoolcore.h

SRCS-y	+= handlereg.c

include $(XEN_ROOT)/tools/libs/libs.mk

PKG_CONFIG_DESC := Central support for Xen Hypervisor userland libraries

$(LIB_OBJS): $(AUTOINCS)
$(PIC_OBJS): $(AUTOINCS)

$(XEN_INCLUDE)/_xentoolcore_list.h: $(XEN_INCLUDE)/xen-external/bsd-sys-queue-h-seddery $(XEN_INCLUDE)/xen-external/bsd-sys-queue.h
	$(PERL) $^ --prefix=xentoolcore >$(notdir $@).new
	$(call move-if-changed,$(notdir $@).new,$@)
