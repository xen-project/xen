XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/libfsimage/Rules.mk

MAJOR = 4.14
MINOR = 0

LDFLAGS-$(CONFIG_SunOS) = -Wl,-M -Wl,mapfile-SunOS
LDFLAGS-$(CONFIG_Linux) = -Wl,mapfile-GNU
LDFLAGS += $(LDFLAGS-y)

CFLAGS += $(PTHREAD_CFLAGS)
LDFLAGS += $(PTHREAD_LDFLAGS)

LIB_SRCS-y = fsimage.c fsimage_plugin.c fsimage_grub.c

PIC_OBJS := $(patsubst %.c,%.opic,$(LIB_SRCS-y))

LIB = libxenfsimage.so libxenfsimage.so.$(MAJOR) libxenfsimage.so.$(MAJOR).$(MINOR)

.PHONY: all
all: $(LIB)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_PROG) libxenfsimage.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	ln -sf libxenfsimage.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxenfsimage.so.$(MAJOR)
	ln -sf libxenfsimage.so.$(MAJOR) $(DESTDIR)$(libdir)/libxenfsimage.so
	$(INSTALL_DATA) xenfsimage.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) xenfsimage_plugin.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) xenfsimage_grub.h $(DESTDIR)$(includedir)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(includedir)/xenfsimage_grub.h
	rm -f $(DESTDIR)$(includedir)/xenfsimage_plugin.h
	rm -f $(DESTDIR)$(includedir)/xenfsimage.h
	rm -f $(DESTDIR)$(libdir)/libxenfsimage.so
	rm -f $(DESTDIR)$(libdir)/libxenfsimage.so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/libxenfsimage.so.$(MAJOR).$(MINOR)

clean distclean::
	rm -f $(LIB)

libxenfsimage.so: libxenfsimage.so.$(MAJOR)
	ln -sf $< $@
libxenfsimage.so.$(MAJOR): libxenfsimage.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenfsimage.so.$(MAJOR).$(MINOR): $(PIC_OBJS)
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenfsimage.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(PTHREAD_LIBS) $(APPEND_LDFLAGS)

-include $(DEPS_INCLUDE)

