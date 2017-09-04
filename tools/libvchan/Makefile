#
# tools/libvchan/Makefile
#

XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

LIBVCHAN_OBJS = init.o io.o
NODE_OBJS = node.o
NODE2_OBJS = node-select.o

LIBVCHAN_PIC_OBJS = $(patsubst %.o,%.opic,$(LIBVCHAN_OBJS))
LIBVCHAN_LIBS = $(LDLIBS_libxenstore) $(LDLIBS_libxengnttab) $(LDLIBS_libxenevtchn)
$(LIBVCHAN_OBJS) $(LIBVCHAN_PIC_OBJS): CFLAGS += $(CFLAGS_libxenstore) $(CFLAGS_libxengnttab) $(CFLAGS_libxenevtchn)
$(NODE_OBJS) $(NODE2_OBJS): CFLAGS += $(CFLAGS_libxengnttab) $(CFLAGS_libxenevtchn)

MAJOR = 4.10
MINOR = 0

CFLAGS += -I../include -I.

io.o io.opic: CFLAGS += $(CFLAGS_libxenctrl) # for xen_mb et al

PKG_CONFIG := xenvchan.pc
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(foreach pc,$(PKG_CONFIG),$(PKG_CONFIG_DIR)/$(pc))

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_LIBVCHAN)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_CFLAGS_LOCAL = $(CFLAGS_xeninclude)

.PHONY: all
all: libxenvchan.so vchan-node1 vchan-node2 libxenvchan.a $(PKG_CONFIG_INST) $(PKG_CONFIG_LOCAL)

libxenvchan.so: libxenvchan.so.$(MAJOR)
	ln -sf $< $@

libxenvchan.so.$(MAJOR): libxenvchan.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenvchan.so.$(MAJOR).$(MINOR): $(LIBVCHAN_PIC_OBJS)
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenvchan.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(LIBVCHAN_LIBS) $(APPEND_LDFLAGS)

libxenvchan.a: $(LIBVCHAN_OBJS)
	$(AR) rcs libxenvchan.a $^

vchan-node1: $(NODE_OBJS) libxenvchan.so
	$(CC) $(LDFLAGS) -o $@ $(NODE_OBJS) $(LDLIBS_libxenvchan) $(APPEND_LDFLAGS)

vchan-node2: $(NODE2_OBJS) libxenvchan.so
	$(CC) $(LDFLAGS) -o $@ $(NODE2_OBJS) $(LDLIBS_libxenvchan) $(APPEND_LDFLAGS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_PROG) libxenvchan.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	ln -sf libxenvchan.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxenvchan.so.$(MAJOR)
	ln -sf libxenvchan.so.$(MAJOR) $(DESTDIR)$(libdir)/libxenvchan.so
	$(INSTALL_DATA) libxenvchan.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) libxenvchan.a $(DESTDIR)$(libdir)
	$(INSTALL_DATA) xenvchan.pc $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/xenvchan.pc
	rm -f $(DESTDIR)$(libdir)/libxenvchan.a
	rm -f $(DESTDIR)$(includedir)/libxenvchan.h
	rm -f $(DESTDIR)$(libdir)/libxenvchan.so
	rm -f $(DESTDIR)$(libdir)/libxenvchan.so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/libxenvchan.so.$(MAJOR).$(MINOR)

.PHONY: clean
clean:
	$(RM) -f *.o *.opic *.so* *.a vchan-node1 vchan-node2 $(DEPS_RM)
	$(RM) -f xenvchan.pc

distclean: clean

-include $(DEPS_INCLUDE)
