#
# tools/libvchan/Makefile
#

XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

LIBVCHAN_OBJS = init.o io.o
NODE_OBJS = node.o
NODE2_OBJS = node-select.o

LIBVCHAN_PIC_OBJS = $(patsubst %.o,%.opic,$(LIBVCHAN_OBJS))
LIBVCHAN_LIBS = $(LDLIBS_libxenstore) $(LDLIBS_libxenctrl)
$(LIBVCHAN_OBJS) $(LIBVCHAN_PIC_OBJS): CFLAGS += $(CFLAGS_libxenstore) $(CFLAGS_libxenctrl)
$(NODE_OBJS) $(NODE2_OBJS): CFLAGS += $(CFLAGS_libxenctrl)

MAJOR = 1.0
MINOR = 0

CFLAGS += -I../include -I.

.PHONY: all
all: libxenvchan.so vchan-node1 vchan-node2 libxenvchan.a

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
	$(INSTALL_DIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_DIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_PROG) libxenvchan.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)
	ln -sf libxenvchan.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libxenvchan.so.$(MAJOR)
	ln -sf libxenvchan.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libxenvchan.so
	$(INSTALL_DATA) libxenvchan.h $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) libxenvchan.a $(DESTDIR)$(LIBDIR)

.PHONY: clean
clean:
	$(RM) -f *.o *.opic *.so* *.a vchan-node1 vchan-node2 $(DEPS)

distclean: clean

-include $(DEPS)
