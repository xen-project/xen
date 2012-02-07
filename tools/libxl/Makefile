#
# tools/libxl/Makefile
#

XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR = 2.0
MINOR = 0

XLUMAJOR = 1.0
XLUMINOR = 0

CFLAGS += -Werror -Wno-format-zero-length -Wmissing-declarations \
	-Wno-declaration-after-statement -Wformat-nonliteral
CFLAGS += -I. -fPIC

ifeq ($(CONFIG_Linux),y)
LIBUUID_LIBS += -luuid
endif

ifeq ($(CONFIG_YAJL_VERSION),y)
CFLAGS += -DHAVE_YAJL_VERSION
endif

LIBXL_LIBS =
LIBXL_LIBS = $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore) $(LDLIBS_libblktapctl) $(UTIL_LIBS) $(LIBUUID_LIBS)

LIBXLU_LIBS =

LIBXL_OBJS-y = osdeps.o libxl_paths.o libxl_bootloader.o flexarray.o
ifeq ($(LIBXL_BLKTAP),y)
LIBXL_OBJS-y += libxl_blktap2.o
else
LIBXL_OBJS-y += libxl_noblktap2.o
endif
LIBXL_OBJS-$(CONFIG_X86) += libxl_cpuid.o
LIBXL_OBJS-$(CONFIG_IA64) += libxl_nocpuid.o

ifeq ($(CONFIG_NetBSD),y)
LIBXL_OBJS-y += libxl_netbsd.o
else
ifeq ($(CONFIG_Linux),y)
LIBXL_OBJS-y += libxl_linux.o
else
$(error Your Operating System is not supported by libxenlight, \
please check libxl_linux.c and libxl_netbsd.c to see how to get it ported)
endif
endif

LIBXL_LIBS += -lyajl

LIBXL_OBJS = flexarray.o libxl.o libxl_create.o libxl_dm.o libxl_pci.o \
			libxl_dom.o libxl_exec.o libxl_xshelp.o libxl_device.o \
			libxl_internal.o libxl_utils.o libxl_uuid.o libxl_json.o \
			libxl_qmp.o libxl_event.o $(LIBXL_OBJS-y)
LIBXL_OBJS += _libxl_types.o libxl_flask.o _libxl_types_internal.o

$(LIBXL_OBJS): CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest) $(CFLAGS_libxenstore) $(CFLAGS_libblktapctl)

AUTOINCS= libxlu_cfg_y.h libxlu_cfg_l.h _libxl_list.h
AUTOSRCS= libxlu_cfg_y.c libxlu_cfg_l.c
LIBXLU_OBJS = libxlu_cfg_y.o libxlu_cfg_l.o libxlu_cfg.o \
	libxlu_disk_l.o libxlu_disk.o
$(LIBXLU_OBJS): CFLAGS += $(CFLAGS_libxenctrl) # For xentoollog.h

CLIENTS = xl testidl

XL_OBJS = xl.o xl_cmdimpl.o xl_cmdtable.o xl_sxp.o
$(XL_OBJS): CFLAGS += $(CFLAGS_libxenctrl) # For xentoollog.h
$(XL_OBJS): CFLAGS += $(CFLAGS_libxenlight)

testidl.o: CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_libxenlight)
testidl.c: libxl_types.idl gentest.py libxl.h $(AUTOINCS)
	$(PYTHON) gentest.py libxl_types.idl testidl.c.new
	mv testidl.c.new testidl.c

.PHONY: all
all: $(CLIENTS) libxenlight.so libxenlight.a libxlutil.so libxlutil.a \
	$(AUTOSRCS) $(AUTOINCS)

$(LIBXL_OBJS) $(LIBXLU_OBJS) $(XL_OBJS): $(AUTOINCS)

%.c %.h: %.y
	@rm -f $*.[ch]
	$(BISON) --output=$*.c $<

%.c %.h: %.l
	@rm -f $*.[ch]
	$(FLEX) --header-file=$*.h --outfile=$*.c $<

genpath-target = $(call buildmakevars2file,_libxl_paths.h.tmp)
$(eval $(genpath-target))

_libxl_paths.h: genpath
	sed -e "s/\([^=]*\)=\(.*\)/#define \1 \2/g" $@.tmp >$@.2.tmp
	rm -f $@.tmp
	$(call move-if-changed,$@.2.tmp,$@)

_libxl_list.h: $(XEN_INCLUDE)/xen-external/bsd-sys-queue-h-seddery $(XEN_INCLUDE)/xen-external/bsd-sys-queue.h
	perl $^ --prefix=libxl >$@.new
	$(call move-if-changed,$@.new,$@)

libxl_paths.c: _libxl_paths.h

libxl.h: _libxl_types.h
libxl_json.h: _libxl_types_json.h
libxl_internal.h: _libxl_types_internal.h
libxl_internal_json.h: _libxl_types_internal_json.h

$(LIBXL_OBJS) $(LIBXLU_OBJS) $(XL_OBJS): libxl.h
$(LIBXL_OBJS): libxl_internal.h

_libxl_type%.h _libxl_type%_json.h _libxl_type%.c: libxl_type%.idl gentypes.py idl.py
	$(PYTHON) gentypes.py libxl_type$*.idl __libxl_type$*.h __libxl_type$*_json.h __libxl_type$*.c
	$(call move-if-changed,__libxl_type$*.h,_libxl_type$*.h)
	$(call move-if-changed,__libxl_type$*_json.h,_libxl_type$*_json.h)
	$(call move-if-changed,__libxl_type$*.c,_libxl_type$*.c)

libxenlight.so: libxenlight.so.$(MAJOR)
	ln -sf $< $@

libxenlight.so.$(MAJOR): libxenlight.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenlight.so.$(MAJOR).$(MINOR): $(LIBXL_OBJS)
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenlight.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(LIBXL_LIBS) $(APPEND_LDFLAGS)

libxenlight.a: $(LIBXL_OBJS)
	$(AR) rcs libxenlight.a $^

libxlutil.so: libxlutil.so.$(XLUMAJOR)
	ln -sf $< $@

libxlutil.so.$(XLUMAJOR): libxlutil.so.$(XLUMAJOR).$(XLUMINOR)
	ln -sf $< $@

libxlutil.so.$(XLUMAJOR).$(XLUMINOR): $(LIBXLU_OBJS)
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxlutil.so.$(XLUMAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(LIBXLU_LIBS) $(APPEND_LDFLAGS)

libxlutil.a: $(LIBXLU_OBJS)
	$(AR) rcs libxlutil.a $^

xl: $(XL_OBJS) libxlutil.so libxenlight.so
	$(CC) $(LDFLAGS) -o $@ $(XL_OBJS) libxlutil.so $(LDLIBS_libxenlight) $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

testidl: testidl.o libxlutil.so libxenlight.so
	$(CC) $(LDFLAGS) -o $@ testidl.o libxlutil.so $(LDLIBS_libxenlight) $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_DIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_DIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DIR) $(DESTDIR)$(BASH_COMPLETION_DIR)
	$(INSTALL_DIR) $(DESTDIR)$(XEN_RUN_DIR)
	$(INSTALL_PROG) xl $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) libxenlight.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)
	ln -sf libxenlight.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libxenlight.so.$(MAJOR)
	ln -sf libxenlight.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libxenlight.so
	$(INSTALL_DATA) libxenlight.a $(DESTDIR)$(LIBDIR)
	$(INSTALL_PROG) libxlutil.so.$(XLUMAJOR).$(XLUMINOR) $(DESTDIR)$(LIBDIR)
	ln -sf libxlutil.so.$(XLUMAJOR).$(XLUMINOR) $(DESTDIR)$(LIBDIR)/libxlutil.so.$(XLUMAJOR)
	ln -sf libxlutil.so.$(XLUMAJOR) $(DESTDIR)$(LIBDIR)/libxlutil.so
	$(INSTALL_DATA) libxlutil.a $(DESTDIR)$(LIBDIR)
	$(INSTALL_DATA) libxl.h libxl_json.h _libxl_types.h _libxl_types_json.h _libxl_list.h libxl_utils.h libxl_uuid.h $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) bash-completion $(DESTDIR)$(BASH_COMPLETION_DIR)/xl.sh

.PHONY: clean
clean:
	$(RM) -f _*.h *.o *.so* *.a $(CLIENTS) $(DEPS)
	$(RM) -f _*.c *.pyc _libxl_paths.*.tmp
	$(RM) -f testidl.c.new testidl.c
#	$(RM) -f $(AUTOSRCS) $(AUTOINCS)

distclean: clean

-include $(DEPS)
