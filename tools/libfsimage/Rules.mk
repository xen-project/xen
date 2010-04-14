include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Wno-unknown-pragmas -I$(XEN_ROOT)/tools/libfsimage/common/
CFLAGS += -Werror -D_GNU_SOURCE
LDFLAGS += -L../common/

PIC_OBJS := $(patsubst %.c,%.opic,$(LIB_SRCS-y))

FSDIR-$(CONFIG_Linux) = $(LIBDIR)/fs/$(FS)
FSDIR-$(CONFIG_SunOS)-x86_64 = $(PREFIX)/lib/fs/$(FS)/64
FSDIR-$(CONFIG_SunOS)-x86_32 = $(PREFIX)/lib/fs/$(FS)/
FSDIR-$(CONFIG_SunOS) = $(FSDIR-$(CONFIG_SunOS)-$(XEN_TARGET_ARCH))
FSDIR-$(CONFIG_NetBSD) = $(LIBDIR)/fs/$(FS)
FSDIR = $(FSDIR-y)

FSLIB = fsimage.so

.PHONY: fs-all
fs-all: $(FSLIB)

.PHONY: fs-install
fs-install: fs-all
	$(INSTALL_DIR) $(DESTDIR)$(FSDIR)
	$(INSTALL_PROG) $(FSLIB) $(DESTDIR)$(FSDIR)

$(FSLIB): $(PIC_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SHLIB_CFLAGS) -o $@ $^ -lfsimage $(FS_LIBDEPS)

clean distclean:
	rm -f $(PIC_OBJS) $(FSLIB) $(DEPS)

-include $(DEPS)
