XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR	= 1
MINOR	= 0
LIBNAME  := toolcore
AUTOINCS := include/_xentoolcore_list.h

SRCS-y	+= handlereg.c

include $(XEN_ROOT)/tools/libs/libs.mk

$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_LIBXENTOOLCORE)/include

$(LIB_OBJS): $(AUTOINCS)
$(PIC_OBJS): $(AUTOINCS)

include/_xentoolcore_list.h: $(XEN_INCLUDE)/xen-external/bsd-sys-queue-h-seddery $(XEN_INCLUDE)/xen-external/bsd-sys-queue.h
	$(PERL) $^ --prefix=xentoolcore >$@.new
	$(call move-if-changed,$@.new,$@)
