#
# tools/libxl/Makefile
#

XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR = 1.0
MINOR = 0

#CFLAGS += -Werror
CFLAGS += -I. -fPIC
CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest) $(CFLAGS_libxenstore)

LIBS = $(LDFLAGS_libxenctrl) $(LDFLAGS_libxenguest) $(LDFLAGS_libxenstore)

LIBXL_OBJS-y = osdeps.o
LIBXL_OBJS = flexarray.o libxl.o libxl_dom.o libxl_exec.o libxl_xshelp.o libxl_device.o libxl_internal.o xenguest.o libxl_utils.o $(LIBXL_OBJS-y)

CLIENTS = xl

.PHONY: all
all: $(CLIENTS) libxenlight.so libxenlight.a

libxenlight.so: libxenlight.so.$(MAJOR)
	ln -sf $< $@

libxenlight.so.$(MAJOR): libxenlight.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenlight.so.$(MAJOR).$(MINOR): $(LIBXL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenlight.so.$(MAJOR) $(SHLIB_CFLAGS) -o $@ $^

libxenlight.a: $(LIBXL_OBJS)
	$(AR) rcs libxenlight.a $^

xl.o: xl.c
	$(CC) $(CFLAGS) -c xl.c

$(CLIENTS): xl.o libxenlight.so
	$(CC) $(LDFLAGS) -o $@ $< $(LIBS) -L . -lxenlight -lconfig

.PHONY: install
install: all
	$(INSTALL_PROG) xl $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) libxenlight.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)
	ln -sf libxenlight.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libxenlight.so.$(MAJOR)
	ln -sf libxenlight.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libxenlight.so
	$(INSTALL_DATA) libxenlight.a $(DESTDIR)$(LIBDIR)
	$(INSTALL_DATA) libxl.h $(DESTDIR)$(INCLUDEDIR)

.PHONY: clean
clean:
	$(RM) -f *.o *.so* *.a $(CLIENTS) $(DEPS)

distclean: clean

-include $(DEPS)
