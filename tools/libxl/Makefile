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

LDFLAGS = $(LDFLAGS_libxenctrl) $(LDFLAGS_libxenguest) $(LDFLAGS_libxenstore) -luuid

LIBCONFIG_URL ?= http://www.hyperrealm.com/libconfig
LIBCONFIG_SOURCE = libconfig-1.3.2
LIBCONFIG_OUTPUT = $(LIBCONFIG_SOURCE)/.libs
WGET=wget -c

LIBXL_OBJS = flexarray.o libxl.o libxl_dom.o libxl_exec.o libxl_xshelp.o libxl_device.o libxl_internal.o xenguest.o osdeps.o libxl_utils.o

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

$(LIBCONFIG_SOURCE).tar.gz:
	$(WGET) $(LIBCONFIG_URL)/$@

$(LIBCONFIG_SOURCE): $(LIBCONFIG_SOURCE).tar.gz
	tar xzf $<

$(LIBCONFIG_OUTPUT)/libconfig.so: $(LIBCONFIG_SOURCE)
	cd $(LIBCONFIG_SOURCE) && ./configure --prefix=$(DESTDIR)$(PREFIX) && $(MAKE)

xl.o: $(LIBCONFIG_SOURCE)
	$(CC) $(CFLAGS) -I$(LIBCONFIG_SOURCE) -c xl.c

$(CLIENTS): xl.o libxenlight.so $(LIBCONFIG_OUTPUT)/libconfig.so
	$(CC) $(LDFLAGS) -o $@ $< -L . -lxenlight -L$(LIBCONFIG_OUTPUT) -lconfig

.PHONY: install
install: all
	$(INSTALL_PROG) xl $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) libxenlight.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)
	ln -sf libxenlight.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libxenlight.so.$(MAJOR)
	ln -sf libxenlight.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libxenlight.so
	$(INSTALL_DATA) libxenlight.a $(DESTDIR)$(LIBDIR)
	cd $(LIBCONFIG_SOURCE) && DESTDIR= $(MAKE) install

.PHONY: clean
clean:
	$(RM) -f *.o *.so* *.a $(CLIENTS)
	$(RM) -rf $(LIBCONFIG_SOURCE)

distclean: clean
	$(RM) -f $(LIBCONFIG_SOURCE).tar.gz

