include $(XEN_ROOT)/tools/Rules.mk

FSDIR := $(libdir)/xenfsimage
CFLAGS += -Wno-unknown-pragmas -I$(XEN_ROOT)/tools/libfsimage/common/ -DFSIMAGE_FSDIR=\"$(FSDIR)\"
CFLAGS += -Werror -D_GNU_SOURCE
LDFLAGS += -L../common/

PIC_OBJS = $(patsubst %.c,%.opic,$(LIB_SRCS-y))

clean distclean::
	rm -f $(PIC_OBJS) $(TARGETS) $(DEPS_RM)
