XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR = 1.0
MINOR = 0

CFLAGS += -Werror -Wp,-MD,.$(@F).d
DEPS = .*.d

LDFLAGS-$(CONFIG_SunOS) = -Wl,-M -Wl,mapfile-SunOS
LDFLAGS-$(CONFIG_Linux) = -Wl,mapfile-GNU
LDFLAGS = $(LDFLAGS-y)

LIB_SRCS-y = fsimage.c fsimage_plugin.c fsimage_grub.c

PIC_OBJS := $(patsubst %.c,%.opic,$(LIB_SRCS-y))

LIB = libfsimage.so libfsimage.so.$(MAJOR) libfsimage.so.$(MAJOR).$(MINOR)

.PHONY: all
all: $(LIB)

.PHONY: install
install: all
	[ -d $(DESTDIR)/usr/$(LIBDIR) ] || $(INSTALL_DIR) $(DESTDIR)/usr/$(LIBDIR)
	[ -d $(DESTDIR)/usr/include ] || $(INSTALL_DIR) $(DESTDIR)/usr/include
	$(INSTALL_PROG) libfsimage.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)
	ln -sf libfsimage.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)/libfsimage.so.$(MAJOR)
	ln -sf libfsimage.so.$(MAJOR) $(DESTDIR)/usr/$(LIBDIR)/libfsimage.so
	$(INSTALL_DATA) fsimage.h $(DESTDIR)/usr/include
	$(INSTALL_DATA) fsimage_plugin.h $(DESTDIR)/usr/include
	$(INSTALL_DATA) fsimage_grub.h $(DESTDIR)/usr/include

clean distclean:
	rm -f $(PIC_OBJS) $(LIB) $(DEPS)

libfsimage.so: libfsimage.so.$(MAJOR)
	ln -sf $< $@
libfsimage.so.$(MAJOR): libfsimage.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libfsimage.so.$(MAJOR).$(MINOR): $(PIC_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libfsimage.so.$(MAJOR) $(SHLIB_CFLAGS) -o $@ $^ -lpthread

-include $(DEPS)

