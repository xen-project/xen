#
# tools/libxl/Makefile
#

XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR = 4.13
MINOR = 0

XLUMAJOR = 4.13
XLUMINOR = 0

CFLAGS += -Werror -Wno-format-zero-length -Wmissing-declarations \
	-Wno-declaration-after-statement -Wformat-nonliteral
CFLAGS += -I. -fPIC

ifeq ($(CONFIG_Linux),y)
LIBUUID_LIBS += -luuid
endif

LIBXL_LIBS =
LIBXL_LIBS = $(LDLIBS_libxentoollog) $(LDLIBS_libxenevtchn) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore) $(LDLIBS_libxentoolcore) $(PTYFUNCS_LIBS) $(LIBUUID_LIBS)
ifeq ($(CONFIG_LIBNL),y)
LIBXL_LIBS += $(LIBNL3_LIBS)
endif

CFLAGS_LIBXL += $(CFLAGS_libxentoollog)
CFLAGS_LIBXL += $(CFLAGS_libxentoolcore)
CFLAGS_LIBXL += $(CFLAGS_libxenevtchn)
CFLAGS_LIBXL += $(CFLAGS_libxenctrl)
CFLAGS_LIBXL += $(CFLAGS_libxenguest)
CFLAGS_LIBXL += $(CFLAGS_libxenstore)
ifeq ($(CONFIG_LIBNL),y)
CFLAGS_LIBXL += $(LIBNL3_CFLAGS)
endif
CFLAGS_LIBXL += -Wshadow
ifeq ($(debug),y)
CFLAGS_LIBXL += -DCONFIG_DEBUG
endif

LIBXL_LIBS-$(CONFIG_ARM) += -lfdt

CFLAGS += $(PTHREAD_CFLAGS)
LDFLAGS += $(PTHREAD_LDFLAGS)
LIBXL_LIBS += $(PTHREAD_LIBS)
LIBXL_LIBS += $(LIBXL_LIBS-y)

LIBXLU_LIBS = $(LDLIBS_libxenlight)

LIBXL_OBJS-y = osdeps.o libxl_paths.o libxl_bootloader.o flexarray.o

ifeq ($(CONFIG_LIBNL),y)
LIBXL_OBJS-y += libxl_netbuffer.o
else
LIBXL_OBJS-y += libxl_nonetbuffer.o
endif

ifeq ($(CONFIG_X86),y)
LIBXL_OBJS-y += libxl_convert_callout.o
else
LIBXL_OBJS-y += libxl_no_convert_callout.o
endif

LIBXL_OBJS-y += libxl_remus.o libxl_checkpoint_device.o libxl_remus_disk_drbd.o

ifeq ($(CONFIG_LIBNL),y)
LIBXL_OBJS-y += libxl_colo_restore.o libxl_colo_save.o
LIBXL_OBJS-y += libxl_colo_qdisk.o
LIBXL_OBJS-y += libxl_colo_proxy.o
LIBXL_OBJS-y += libxl_colo_nic.o
else
LIBXL_OBJS-y += libxl_no_colo.o
endif

ACPI_PATH  = $(XEN_ROOT)/tools/libacpi
DSDT_FILES-$(CONFIG_X86) = dsdt_pvh.c
ACPI_OBJS  = $(patsubst %.c,%.o,$(DSDT_FILES-y)) build.o static_tables.o
$(DSDT_FILES-y): acpi
$(ACPI_OBJS): CFLAGS += -I. -DLIBACPI_STDUTILS=\"$(CURDIR)/libxl_x86_acpi.h\"
vpath build.c $(ACPI_PATH)/
vpath static_tables.c $(ACPI_PATH)/
LIBXL_OBJS-$(CONFIG_X86) += $(ACPI_OBJS)

.PHONY: acpi
acpi:
	$(MAKE) -C $(ACPI_PATH) ACPI_BUILD_DIR=$(CURDIR) DSDT_FILES="$(DSDT_FILES-y)"

LIBXL_OBJS-$(CONFIG_X86) += libxl_cpuid.o libxl_x86.o libxl_psr.o libxl_x86_acpi.o
LIBXL_OBJS-$(CONFIG_ARM) += libxl_nocpuid.o libxl_arm.o libxl_libfdt_compat.o
ifeq ($(CONFIG_ARM_64),y)
DSDT_FILES-y = dsdt_anycpu_arm.c
LIBXL_OBJS-y += libxl_arm_acpi.o $(patsubst %.c,%.o,$(DSDT_FILES-y))
dsdt_anycpu_arm.c:
	$(MAKE) -C $(ACPI_PATH) ACPI_BUILD_DIR=$(CURDIR) DSDT_FILES="$(DSDT_FILES-y)"
else
LIBXL_OBJS-$(CONFIG_ARM) += libxl_arm_no_acpi.o
endif

ifeq ($(CONFIG_NetBSD),y)
LIBXL_OBJS-y += libxl_netbsd.o
else
ifeq ($(CONFIG_Linux),y)
LIBXL_OBJS-y += libxl_linux.o
else
ifeq ($(CONFIG_FreeBSD),y)
LIBXL_OBJS-y += libxl_freebsd.o
else
$(error Your Operating System is not supported by libxenlight, \
please check libxl_linux.c and libxl_netbsd.c to see how to get it ported)
endif
endif
endif

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

LIBXL_LIBS += -lyajl

LIBXL_OBJS = flexarray.o libxl.o libxl_create.o libxl_dm.o libxl_pci.o \
			libxl_dom.o libxl_exec.o libxl_xshelp.o libxl_device.o \
			libxl_internal.o libxl_utils.o libxl_uuid.o \
			libxl_json.o libxl_aoutils.o libxl_numa.o libxl_vnuma.o \
			libxl_stream_read.o libxl_stream_write.o \
			libxl_save_callout.o _libxl_save_msgs_callout.o \
			libxl_qmp.o libxl_event.o libxl_fork.o \
			libxl_dom_suspend.o libxl_dom_save.o libxl_usb.o \
			libxl_vtpm.o libxl_nic.o libxl_disk.o libxl_console.o \
			libxl_cpupool.o libxl_mem.o libxl_sched.o libxl_tmem.o \
			libxl_9pfs.o libxl_domain.o libxl_vdispl.o \
			libxl_pvcalls.o libxl_vsnd.o libxl_vkb.o $(LIBXL_OBJS-y)
LIBXL_OBJS += libxl_genid.o
LIBXL_OBJS += _libxl_types.o libxl_flask.o _libxl_types_internal.o

LIBXL_TESTS += timedereg
LIBXL_TESTS_PROGS = $(LIBXL_TESTS) fdderegrace
LIBXL_TESTS_INSIDE = $(LIBXL_TESTS) fdevent

# Each entry FOO in LIBXL_TESTS has two main .c files:
#   libxl_test_FOO.c  "inside libxl" code to support the test case
#   test_FOO.c        "outside libxl" code to exercise the test case
# Conventionally there will also be:
#   libxl_test_FOO.h  interface between the "inside" and "outside" parts
# The "inside libxl" file is compiled exactly like a piece of libxl, and the
# "outside libxl" file is compiled exactly like a piece of application
# code.  They must share information via explicit libxl entrypoints.
# Unlike proper parts of libxl, it is permissible for libxl_test_FOO.c
# to use private global variables for its state.  Note that all the
# "inside" parts are compiled into a single test library, so their
# symbol names must be unique.
#
# To run these tests, either use LD_PRELOAD to get libxenlight_test.so
# loaded, or rename it to libxenlight.so so it is the target of the
# appropriate symlinks.

LIBXL_TEST_OBJS += $(foreach t, $(LIBXL_TESTS_INSIDE),libxl_test_$t.o)
TEST_PROG_OBJS += $(foreach t, $(LIBXL_TESTS_PROGS),test_$t.o) test_common.o
TEST_PROGS += $(foreach t, $(LIBXL_TESTS_PROGS),test_$t)

$(LIBXL_OBJS) $(LIBXL_TEST_OBJS): CFLAGS += $(CFLAGS_LIBXL) -include $(XEN_ROOT)/tools/config.h

AUTOINCS= libxlu_cfg_y.h libxlu_cfg_l.h _libxl_list.h _paths.h \
	libxlu_disk_l.h _libxl_save_msgs_callout.h _libxl_save_msgs_helper.h
AUTOSRCS= libxlu_cfg_y.c libxlu_cfg_l.c
AUTOSRCS += _libxl_save_msgs_callout.c _libxl_save_msgs_helper.c
LIBXLU_OBJS = libxlu_cfg_y.o libxlu_cfg_l.o libxlu_cfg.o \
	libxlu_disk_l.o libxlu_disk.o libxlu_vif.o libxlu_pci.o
$(LIBXLU_OBJS): CFLAGS += $(CFLAGS_libxenctrl) # For xentoollog.h

$(TEST_PROG_OBJS) _libxl.api-for-check: CFLAGS += $(CFLAGS_libxentoollog) $(CFLAGS_libxentoolcore)

CLIENTS = testidl libxl-save-helper

libxl_dom.o: CFLAGS += -I$(XEN_ROOT)/tools  # include libacpi/x86.h
libxl_x86_acpi.o: CFLAGS += -I$(XEN_ROOT)/tools

SAVE_HELPER_OBJS = libxl_save_helper.o _libxl_save_msgs_helper.o
$(SAVE_HELPER_OBJS): CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_libxenevtchn)

PKG_CONFIG = xenlight.pc xlutil.pc
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
xenlight.pc: PKG_CONFIG_VERSION = $(MAJOR).$(MINOR)
xlutil.pc: PKG_CONFIG_VERSION = $(XLUMAJOR).$(XLUMINOR)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(foreach pc,$(PKG_CONFIG),$(PKG_CONFIG_DIR)/$(pc))

$(PKG_CONFIG_DIR)/xenlight.pc: PKG_CONFIG_VERSION = $(MAJOR).$(MINOR)
$(PKG_CONFIG_DIR)/xlutil.pc: PKG_CONFIG_VERSION = $(XLUMAJOR).$(XLUMINOR)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(CURDIR)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_CFLAGS_LOCAL = $(CFLAGS_xeninclude)

testidl.o: CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_libxenlight)
testidl.c: libxl_types.idl gentest.py libxl.h $(AUTOINCS)
	$(PYTHON) gentest.py libxl_types.idl testidl.c.new
	mv testidl.c.new testidl.c

.PHONY: all
all: $(CLIENTS) $(TEST_PROGS) $(PKG_CONFIG) $(PKG_CONFIG_LOCAL) \
		libxenlight.so libxenlight.a libxlutil.so libxlutil.a \
	$(AUTOSRCS) $(AUTOINCS)

$(LIBXL_OBJS) $(LIBXLU_OBJS) $(SAVE_HELPER_OBJS) \
		$(LIBXL_TEST_OBJS) $(TEST_PROG_OBJS): \
	$(AUTOINCS) libxl.api-ok

%.c %.h:: %.y
	@rm -f $*.[ch]
	$(BISON) --output=$*.c $<

%.c %.h:: %.l
	@rm -f $*.[ch]
	$(FLEX) --header-file=$*.h --outfile=$*.c $<

genpath-target = $(call buildmakevars2header,_paths.h)
$(eval $(genpath-target))

libxl.api-ok: check-libxl-api-rules _libxl.api-for-check
	$(PERL) $^
	touch $@

_%.api-for-check: %.h $(AUTOINCS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_$*.o) -c -E $< $(APPEND_CFLAGS) \
		-DLIBXL_EXTERNAL_CALLERS_ONLY=LIBXL_EXTERNAL_CALLERS_ONLY \
		>$@.new
	mv -f $@.new $@

_libxl_list.h: $(XEN_INCLUDE)/xen-external/bsd-sys-queue-h-seddery $(XEN_INCLUDE)/xen-external/bsd-sys-queue.h
	$(PERL) $^ --prefix=libxl >$@.new
	$(call move-if-changed,$@.new,$@)

_libxl_save_msgs_helper.c _libxl_save_msgs_callout.c \
_libxl_save_msgs_helper.h _libxl_save_msgs_callout.h: \
		libxl_save_msgs_gen.pl
	$(PERL) -w $< $@ >$@.new
	$(call move-if-changed,$@.new,$@)

libxl.h: _libxl_types.h _libxl_list.h
libxl_json.h: _libxl_types_json.h
libxl_internal.h: _libxl_types_internal.h _libxl_types_private.h _libxl_types_internal_private.h _paths.h
libxl_internal_json.h: _libxl_types_internal_json.h
xl.h: _paths.h

$(LIBXL_OBJS) $(LIBXL_TEST_OBJS) $(LIBXLU_OBJS) \
	$(TEST_PROG_OBJS) $(SAVE_HELPER_OBJS): libxl.h
$(LIBXL_OBJS) $(LIBXL_TEST_OBJS): libxl_internal.h

_libxl_type%.h _libxl_type%_json.h _libxl_type%_private.h _libxl_type%.c: libxl_type%.idl gentypes.py idl.py
	$(eval stem = $(notdir $*))
	$(PYTHON) gentypes.py libxl_type$(stem).idl __libxl_type$(stem).h __libxl_type$(stem)_private.h \
		__libxl_type$(stem)_json.h  __libxl_type$(stem).c
	$(call move-if-changed,__libxl_type$(stem).h,_libxl_type$(stem).h)
	$(call move-if-changed,__libxl_type$(stem)_private.h,_libxl_type$(stem)_private.h)
	$(call move-if-changed,__libxl_type$(stem)_json.h,_libxl_type$(stem)_json.h)
	$(call move-if-changed,__libxl_type$(stem).c,_libxl_type$(stem).c)

libxenlight.so: libxenlight.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@

libxenlight.so.$(MAJOR): libxenlight.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxenlight.so.$(MAJOR).$(MINOR): $(LIBXL_OBJS)
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenlight.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(LIBXL_LIBS) $(APPEND_LDFLAGS)

libxenlight_test.so: $(LIBXL_OBJS) $(LIBXL_TEST_OBJS)
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenlight.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(LIBXL_LIBS) $(APPEND_LDFLAGS)

libxenlight.a: $(LIBXL_OBJS)
	$(AR) rcs libxenlight.a $^

libxlutil.so: libxlutil.so.$(XLUMAJOR)
	$(SYMLINK_SHLIB) $< $@

libxlutil.so.$(XLUMAJOR): libxlutil.so.$(XLUMAJOR).$(XLUMINOR)
	$(SYMLINK_SHLIB) $< $@

libxlutil.so.$(XLUMAJOR).$(XLUMINOR): $(LIBXLU_OBJS) libxenlight.so
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxlutil.so.$(XLUMAJOR) $(SHLIB_LDFLAGS) -o $@ $(LIBXLU_OBJS) $(LIBXLU_LIBS) $(APPEND_LDFLAGS)

libxlutil.a: $(LIBXLU_OBJS)
	$(AR) rcs libxlutil.a $^

test_%: test_%.o test_common.o libxlutil.so libxenlight_test.so
	$(CC) $(LDFLAGS) -o $@ $^ $(filter-out %libxenlight.so, $(LDLIBS_libxenlight)) $(LDLIBS_libxentoollog) $(LDLIBS_libxentoolcore) -lyajl $(APPEND_LDFLAGS)

libxl-save-helper: $(SAVE_HELPER_OBJS) libxenlight.so
	$(CC) $(LDFLAGS) -o $@ $(SAVE_HELPER_OBJS) $(LDLIBS_libxentoollog) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxentoolcore) $(APPEND_LDFLAGS)

testidl: testidl.o libxlutil.so libxenlight.so
	$(CC) $(LDFLAGS) -o $@ testidl.o libxlutil.so $(LDLIBS_libxenlight) $(LDLIBS_libxentoollog) $(LDLIBS_libxentoolcore) $(APPEND_LDFLAGS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) libxl-save-helper $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_SHLIB) libxenlight.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxenlight.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxenlight.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxenlight.so.$(MAJOR) $(DESTDIR)$(libdir)/libxenlight.so
	$(INSTALL_DATA) libxenlight.a $(DESTDIR)$(libdir)
	$(INSTALL_SHLIB) libxlutil.so.$(XLUMAJOR).$(XLUMINOR) $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxlutil.so.$(XLUMAJOR).$(XLUMINOR) $(DESTDIR)$(libdir)/libxlutil.so.$(XLUMAJOR)
	$(SYMLINK_SHLIB) libxlutil.so.$(XLUMAJOR) $(DESTDIR)$(libdir)/libxlutil.so
	$(INSTALL_DATA) libxlutil.a $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxl.h libxl_event.h libxl_json.h _libxl_types.h _libxl_types_json.h _libxl_list.h libxl_utils.h libxl_uuid.h libxlutil.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) xenlight.pc $(DESTDIR)$(PKG_INSTALLDIR)
	$(INSTALL_DATA) xlutil.pc $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uninstall
uninstall:
	rm -f $(addprefix $(DESTDIR)$(PKG_INSTALLDIR)/,xlutil.pc xenlight.pc)
	rm -f $(addprefix $(DESTDIR)$(includedir)/,libxl.h libxl_event.h libxl_json.h _libxl_types.h _libxl_types_json.h _libxl_list.h libxl_utils.h libxl_uuid.h libxlutil.h)
	rm -f $(DESTDIR)$(libdir)/libxlutil.a
	rm -f $(DESTDIR)$(libdir)/libxlutil.so
	rm -f $(DESTDIR)$(libdir)/libxlutil.so.$(XLUMAJOR)
	rm -f $(DESTDIR)$(libdir)/libxlutil.so.$(XLUMAJOR).$(XLUMINOR)
	rm -f $(DESTDIR)$(libdir)/libxenlight.a
	rm -f $(DESTDIR)$(libdir)/libxenlight.so
	rm -f $(DESTDIR)$(libdir)/libxenlight.so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/libxenlight.so.$(MAJOR).$(MINOR)
	rm -f $(DESTDIR)$(LIBEXEC_BIN)/libxl-save-helper

.PHONY: clean
clean:
	$(RM) -f _*.h *.o *.so* *.a $(CLIENTS) $(DEPS_RM)
	$(RM) -f _*.c *.pyc _paths.*.tmp _*.api-for-check
	$(RM) -f testidl.c.new testidl.c *.api-ok
	$(RM) -f xenlight.pc
	$(RM) -f xlutil.pc
	$(MAKE) -C $(ACPI_PATH) ACPI_BUILD_DIR=$(CURDIR) clean

distclean: clean

realclean: distclean
	$(RM) -f $(AUTOSRCS) $(AUTOINCS)

-include $(DEPS_INCLUDE)
