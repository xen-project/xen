#
# tools/libxl/Makefile
#

XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

XLUMAJOR = 4.15
XLUMINOR = 0

CFLAGS += -Werror -Wno-format-zero-length -Wmissing-declarations \
	-Wno-declaration-after-statement -Wformat-nonliteral
CFLAGS += -I. -fPIC

CFLAGS += $(PTHREAD_CFLAGS)
LDFLAGS += $(PTHREAD_LDFLAGS)

LIBXLU_LIBS = $(LDLIBS_libxenlight)

ifeq ($(FLEX),)
%.c %.h:: %.l
	$(warning Flex is needed to rebuild some libxl parsers and \
		  scanners, please install it and rerun configure)
endif

ifeq ($(BISON),)
%.c %.h:: %.y
	$(warning Bison is needed to rebuild some libxl parsers and \
		  scanners, please install it an rerun configure)
endif

AUTOINCS= libxlu_cfg_y.h libxlu_cfg_l.h libxlu_disk_l.h
AUTOSRCS= libxlu_cfg_y.c libxlu_cfg_l.c
LIBXLU_OBJS = libxlu_cfg_y.o libxlu_cfg_l.o libxlu_cfg.o \
	libxlu_disk_l.o libxlu_disk.o libxlu_vif.o libxlu_pci.o
$(LIBXLU_OBJS): CFLAGS += $(CFLAGS_libxenctrl) # For xentoollog.h

PKG_CONFIG = xlutil.pc

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
xlutil.pc: PKG_CONFIG_NAME = Xlutil
xlutil.pc: PKG_CONFIG_DESC = The xl utility library for Xen hypervisor
xlutil.pc: PKG_CONFIG_VERSION = $(XLUMAJOR).$(XLUMINOR)
xlutil.pc: PKG_CONFIG_USELIBS = $(SHLIB_libxlutil)
xlutil.pc: PKG_CONFIG_LIB = xlutil
xlutil.pc: PKG_CONFIG_REQPRIV = xenlight
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(foreach pc,$(PKG_CONFIG),$(PKG_CONFIG_DIR)/$(pc))

$(PKG_CONFIG_DIR)/xlutil.pc: PKG_CONFIG_NAME = Xlutil
$(PKG_CONFIG_DIR)/xlutil.pc: PKG_CONFIG_DESC = The xl utility library for Xen hypervisor
$(PKG_CONFIG_DIR)/xlutil.pc: PKG_CONFIG_VERSION = $(XLUMAJOR).$(XLUMINOR)
$(PKG_CONFIG_DIR)/xlutil.pc: PKG_CONFIG_USELIBS = $(SHLIB_libxlutil)
$(PKG_CONFIG_DIR)/xlutil.pc: PKG_CONFIG_LIB = xlutil
$(PKG_CONFIG_DIR)/xlutil.pc: PKG_CONFIG_REQPRIV = xenlight
$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(CURDIR)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_CFLAGS_LOCAL = $(CFLAGS_xeninclude)

.PHONY: all
all: libxlutil.so libxlutil.a $(AUTOSRCS) $(AUTOINCS) $(PKG_CONFIG) $(PKG_CONFIG_LOCAL)

$(LIBXLU_OBJS): $(AUTOINCS)

%.c %.h:: %.y
	@rm -f $*.[ch]
	$(BISON) --output=$*.c $<

%.c %.h:: %.l
	@rm -f $*.[ch]
	$(FLEX) --header-file=$*.h --outfile=$*.c $<

genpath-target = $(call buildmakevars2header,_paths.h)
$(eval $(genpath-target))

libxlutil.so: libxlutil.so.$(XLUMAJOR)
	$(SYMLINK_SHLIB) $< $@

libxlutil.so.$(XLUMAJOR): libxlutil.so.$(XLUMAJOR).$(XLUMINOR)
	$(SYMLINK_SHLIB) $< $@

libxlutil.so.$(XLUMAJOR).$(XLUMINOR): $(LIBXLU_OBJS)
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxlutil.so.$(XLUMAJOR) $(SHLIB_LDFLAGS) -o $@ $(LIBXLU_OBJS) $(LIBXLU_LIBS) $(APPEND_LDFLAGS)

libxlutil.a: $(LIBXLU_OBJS)
	$(AR) rcs libxlutil.a $^

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxlutil.so.$(XLUMAJOR).$(XLUMINOR) $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxlutil.so.$(XLUMAJOR).$(XLUMINOR) $(DESTDIR)$(libdir)/libxlutil.so.$(XLUMAJOR)
	$(SYMLINK_SHLIB) libxlutil.so.$(XLUMAJOR) $(DESTDIR)$(libdir)/libxlutil.so
	$(INSTALL_DATA) libxlutil.a $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxlutil.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) xlutil.pc $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/xlutil.pc
	rm -f $(DESTDIR)$(includedir)/libxlutil.h
	rm -f $(DESTDIR)$(libdir)/libxlutil.a
	rm -f $(DESTDIR)$(libdir)/libxlutil.so
	rm -f $(DESTDIR)$(libdir)/libxlutil.so.$(XLUMAJOR)
	rm -f $(DESTDIR)$(libdir)/libxlutil.so.$(XLUMAJOR).$(XLUMINOR)

.PHONY: clean
clean:
	$(RM) -f _*.h *.o *.so* *.a $(DEPS_RM)
	$(RM) -f xlutil.pc

distclean: clean

realclean: distclean
	$(RM) -f $(AUTOSRCS) $(AUTOINCS)

-include $(DEPS_INCLUDE)
