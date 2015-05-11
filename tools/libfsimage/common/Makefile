XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/libfsimage/Rules.mk

MAJOR = 1.0
MINOR = 0

LDFLAGS-$(CONFIG_SunOS) = -Wl,-M -Wl,mapfile-SunOS
LDFLAGS-$(CONFIG_Linux) = -Wl,mapfile-GNU
LDFLAGS = $(LDFLAGS-y)

CFLAGS += $(PTHREAD_CFLAGS)
LDFLAGS += $(PTHREAD_LDFLAGS)

LIB_SRCS-y = fsimage.c fsimage_plugin.c fsimage_grub.c

PIC_OBJS := $(patsubst %.c,%.opic,$(LIB_SRCS-y))

LIB = libfsimage.so libfsimage.so.$(MAJOR) libfsimage.so.$(MAJOR).$(MINOR)

.PHONY: all
all: $(LIB)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_PROG) libfsimage.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	ln -sf libfsimage.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libfsimage.so.$(MAJOR)
	ln -sf libfsimage.so.$(MAJOR) $(DESTDIR)$(libdir)/libfsimage.so
	$(INSTALL_DATA) fsimage.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) fsimage_plugin.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) fsimage_grub.h $(DESTDIR)$(includedir)

clean distclean::
	rm -f $(LIB)

libfsimage.so: libfsimage.so.$(MAJOR)
	ln -sf $< $@
libfsimage.so.$(MAJOR): libfsimage.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libfsimage.so.$(MAJOR).$(MINOR): $(PIC_OBJS)
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libfsimage.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(PTHREAD_LIBS) $(APPEND_LDFLAGS)

-include $(DEPS)

