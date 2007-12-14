include $(XEN_ROOT)/tools/Rules.mk

DEPS = .*.d

CFLAGS += -I$(XEN_ROOT)/tools/libfsimage/common/ -Werror -Wp,-MD,.$(@F).d
LDFLAGS += -L../common/

PIC_OBJS := $(patsubst %.c,%.opic,$(LIB_SRCS-y))

FSDIR-$(CONFIG_Linux) = $(LIBDIR)/fs/$(FS)
FSDIR-$(CONFIG_SunOS)-x86_64 = lib/fs/$(FS)/64
FSDIR-$(CONFIG_SunOS)-x86_32 = lib/fs/$(FS)/
FSDIR-$(CONFIG_SunOS) = $(FSDIR-$(CONFIG_SunOS)-$(XEN_TARGET_ARCH))
FSDIR = $(FSDIR-y)

FSLIB = fsimage.so

.PHONY: fs-all
fs-all: $(FSLIB)

.PHONY: fs-install
fs-install: fs-all
	$(INSTALL_DIR) $(DESTDIR)/usr/$(FSDIR)
	$(INSTALL_PROG) $(FSLIB) $(DESTDIR)/usr/$(FSDIR)

$(FSLIB): $(PIC_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SHLIB_CFLAGS) -o $@ $^ -lfsimage $(FS_LIBDEPS)

clean distclean:
	rm -f $(PIC_OBJS) $(FSLIB) $(DEPS)

-include $(DEPS)
