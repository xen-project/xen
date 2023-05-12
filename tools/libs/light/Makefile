XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

OBJS-y += osdeps.o
OBJS-y += libxl_paths.o
OBJS-y += libxl_bootloader.o
OBJS-y += flexarray.o
ifeq ($(CONFIG_LIBNL),y)
OBJS-y += libxl_netbuffer.o
else
OBJS-y += libxl_nonetbuffer.o
endif
ifeq ($(CONFIG_X86),y)
OBJS-y += libxl_convert_callout.o
else
OBJS-y += libxl_no_convert_callout.o
endif
OBJS-y += libxl_remus.o
OBJS-y += libxl_checkpoint_device.o
OBJS-y += libxl_remus_disk_drbd.o
ifeq ($(CONFIG_LIBNL),y)
OBJS-y += libxl_colo_restore.o
OBJS-y += libxl_colo_save.o
OBJS-y += libxl_colo_qdisk.o
OBJS-y += libxl_colo_proxy.o
OBJS-y += libxl_colo_nic.o
else
OBJS-y += libxl_no_colo.o
endif

ACPI_PATH  = $(XEN_ROOT)/tools/libacpi
DSDT_FILES-$(CONFIG_X86) = dsdt_pvh.c
ACPI_OBJS  = $(patsubst %.c,%.o,$(DSDT_FILES-y)) build.o static_tables.o
ACPI_PIC_OBJS = $(patsubst %.o,%.opic,$(ACPI_OBJS))

vpath build.c $(ACPI_PATH)/
vpath static_tables.c $(ACPI_PATH)/

OBJS-$(CONFIG_X86) += $(ACPI_OBJS)

CFLAGS += -Wno-format-zero-length -Wmissing-declarations \
	-Wno-declaration-after-statement -Wformat-nonliteral

CFLAGS-$(CONFIG_X86) += -DCONFIG_PCI_SUPP_LEGACY_IRQ

OBJS-$(CONFIG_X86) += libxl_cpuid.o
OBJS-$(CONFIG_X86) += libxl_x86.o
OBJS-$(CONFIG_X86) += libxl_psr.o
OBJS-$(CONFIG_X86) += libxl_x86_acpi.o
OBJS-$(CONFIG_ARM) += libxl_nocpuid.o
OBJS-$(CONFIG_ARM) += libxl_arm.o
OBJS-$(CONFIG_ARM) += libxl_libfdt_compat.o
ifeq ($(CONFIG_ARM_64),y)
DSDT_FILES-y = dsdt_anycpu_arm.c
OBJS-y += libxl_arm_acpi.o
OBJS-y += $(DSDT_FILES-y:.c=.o)
else
OBJS-$(CONFIG_ARM) += libxl_arm_no_acpi.o
endif

OBJS-OS-$(CONFIG_NetBSD) = libxl_netbsd.o
OBJS-OS-$(CONFIG_Linux) = libxl_linux.o libxl_setresuid.o
OBJS-OS-$(CONFIG_FreeBSD) = libxl_freebsd.o libxl_setresuid.o
ifeq ($(OBJS-OS-y),)
$(error Your Operating System is not supported by libxenlight, \
please check libxl_linux.c and libxl_netbsd.c to see how to get it ported)
endif
OBJS-y += $(OBJS-OS-y)

OBJS-y += libxl.o
OBJS-y += libxl_create.o
OBJS-y += libxl_dm.o
OBJS-y += libxl_pci.o
OBJS-y += libxl_dom.o
OBJS-y += libxl_exec.o
OBJS-y += libxl_xshelp.o
OBJS-y += libxl_device.o
OBJS-y += libxl_internal.o
OBJS-y += libxl_utils.o
OBJS-y += libxl_uuid.o
OBJS-y += libxl_json.o
OBJS-y += libxl_aoutils.o
OBJS-y += libxl_numa.o
OBJS-y += libxl_vnuma.o
OBJS-y += libxl_stream_read.o
OBJS-y += libxl_stream_write.o
OBJS-y += libxl_save_callout.o
OBJS-y += _libxl_save_msgs_callout.o
OBJS-y += libxl_qmp.o
OBJS-y += libxl_event.o
OBJS-y += libxl_fork.o
OBJS-y += libxl_dom_suspend.o
OBJS-y += libxl_dom_save.o
OBJS-y += libxl_usb.o
OBJS-y += libxl_vtpm.o
OBJS-y += libxl_nic.o
OBJS-y += libxl_disk.o
OBJS-y += libxl_console.o
OBJS-y += libxl_cpupool.o
OBJS-y += libxl_mem.o
OBJS-y += libxl_sched.o
OBJS-y += libxl_tmem.o
OBJS-y += libxl_9pfs.o
OBJS-y += libxl_domain.o
OBJS-y += libxl_vdispl.o
OBJS-y += libxl_pvcalls.o
OBJS-y += libxl_vsnd.o
OBJS-y += libxl_vkb.o
OBJS-y += libxl_virtio.o
OBJS-y += libxl_genid.o
OBJS-y += _libxl_types.o
OBJS-y += libxl_flask.o
OBJS-y += _libxl_types_internal.o

ifeq ($(CONFIG_LIBNL),y)
CFLAGS_LIBXL += $(LIBNL3_CFLAGS)
endif
CFLAGS_LIBXL += -Wshadow
ifeq ($(debug),y)
CFLAGS_LIBXL += -DCONFIG_DEBUG
endif

CFLAGS += $(PTHREAD_CFLAGS)
LDFLAGS += $(PTHREAD_LDFLAGS)

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

LIBXL_TEST_OBJS += $(foreach t, $(LIBXL_TESTS_INSIDE),libxl_test_$t.opic)
TEST_PROG_OBJS += $(foreach t, $(LIBXL_TESTS_PROGS),test_$t.o) test_common.o
TEST_PROGS += $(foreach t, $(LIBXL_TESTS_PROGS),test_$t)

CLIENTS = testidl libxl-save-helper

SAVE_HELPER_OBJS = libxl_save_helper.o _libxl_save_msgs_helper.o

LIBHEADER := libxl.h libxl_event.h libxl_json.h _libxl_types.h _libxl_types_json.h libxl_utils.h libxl_uuid.h

NO_HEADERS_CHK := y

include $(XEN_ROOT)/tools/libs/libs.mk

LDLIBS-y += $(UTIL_LIBS)
LDLIBS-$(CONFIG_LIBNL) += $(LIBNL3_LIBS)
LDLIBS-$(CONFIG_Linux) += -luuid
LDLIBS-$(CONFIG_Linux) += -lrt
LDLIBS-$(CONFIG_ARM) += -lfdt
LDLIBS-y += $(PTHREAD_LIBS)
LDLIBS-y += -lyajl
LDLIBS += $(LDLIBS-y)

$(OBJS-y) $(PIC_OBJS) $(LIBXL_TEST_OBJS): CFLAGS += $(CFLAGS_LIBXL) -include $(XEN_ROOT)/tools/config.h
$(ACPI_OBJS) $(ACPI_PIC_OBJS): CFLAGS += -I. -DLIBACPI_STDUTILS=\"$(CURDIR)/libxl_x86_acpi.h\"
$(TEST_PROG_OBJS) _libxl.api-for-check: CFLAGS += $(CFLAGS_libxentoollog) $(CFLAGS_libxentoolcore)
libxl_x86_acpi.o libxl_x86_acpi.opic: CFLAGS += -iquote $(ACPI_PATH)
$(SAVE_HELPER_OBJS): CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_libxenevtchn) $(CFLAGS_libxenguest)

testidl.o: CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_libxenlight)
testidl.c: libxl_types.idl gentest.py
	$(PYTHON) gentest.py $< $@.new
	mv -f $@.new $@

all: $(CLIENTS) $(TEST_PROGS)

$(OBJS-y) $(PIC_OBJS) $(SAVE_HELPER_OBJS) $(LIBXL_TEST_OBJS) $(TEST_PROG_OBJS): libxl.api-ok

$(DSDT_FILES-y): acpi

# Depend on the source files generated by the "acpi" target even though
# "build.o" don't needs them.  It does need the generated headers.
build.o build.opic: $(DSDT_FILES-y)

libxl.api-ok: check-libxl-api-rules _libxl.api-for-check
	$(PERL) $^
	touch $@

_libxl.api-for-check: $(XEN_INCLUDE)/libxl.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -E $< $(APPEND_CFLAGS) \
		-DLIBXL_EXTERNAL_CALLERS_ONLY=LIBXL_EXTERNAL_CALLERS_ONLY \
		>$@.new
	mv -f $@.new $@

_libxl_save_msgs_helper.c _libxl_save_msgs_callout.c \
_libxl_save_msgs_helper.h _libxl_save_msgs_callout.h: \
		libxl_save_msgs_gen.pl
	$(PERL) -w $< $@ >$@.new
	$(call move-if-changed,$@.new,$@)

#
# headers dependencies on generated headers
#
$(XEN_INCLUDE)/libxl.h: $(XEN_INCLUDE)/_libxl_types.h
$(XEN_INCLUDE)/libxl_json.h: $(XEN_INCLUDE)/_libxl_types_json.h
libxl_internal.h: $(XEN_INCLUDE)/libxl.h $(XEN_INCLUDE)/libxl_json.h
libxl_internal.h: _libxl_types_internal.h _libxl_types_private.h _libxl_types_internal_private.h
libxl_internal.h: _libxl_save_msgs_callout.h

#
# objects dependencies on headers that depends on generated headers
#
$(TEST_PROG_OBJS): $(XEN_INCLUDE)/libxl.h
$(OBJS-y) $(PIC_OBJS) $(LIBXL_TEST_OBJS): libxl_internal.h
$(SAVE_HELPER_OBJS): $(XEN_INCLUDE)/libxl.h _libxl_save_msgs_helper.h
testidl.o: $(XEN_INCLUDE)/libxl.h

# This exploits the 'multi-target pattern rule' trick.
# gentypes.py should be executed only once to make all the targets.
_libxl_type%.h _libxl_type%_json.h _libxl_type%_private.h _libxl_type%.c: libxl_type%.idl gentypes.py idl.py
	$(PYTHON) gentypes.py libxl_type$(*F).idl __libxl_type$(*F).h __libxl_type$(*F)_private.h \
		__libxl_type$(*F)_json.h  __libxl_type$(*F).c
	$(call move-if-changed,__libxl_type$(*F).h,_libxl_type$(*F).h)
	$(call move-if-changed,__libxl_type$(*F)_private.h,_libxl_type$(*F)_private.h)
	$(call move-if-changed,__libxl_type$(*F)_json.h,_libxl_type$(*F)_json.h)
	$(call move-if-changed,__libxl_type$(*F).c,_libxl_type$(*F).c)

.PRECIOUS: _libxl_type%.h _libxl_type%.c

$(XEN_INCLUDE)/_libxl_%.h: _libxl_%.h
	cp -f $< $@

.PHONY: acpi
acpi:
	$(MAKE) -C $(ACPI_PATH) ACPI_BUILD_DIR=$(CURDIR) DSDT_FILES="$(DSDT_FILES-y)"

libxenlight_test.so: $(PIC_OBJS) $(LIBXL_TEST_OBJS)
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenlight.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(LDLIBS) $(APPEND_LDFLAGS)

test_%: test_%.o test_common.o libxenlight_test.so
	$(CC) $(LDFLAGS) -o $@ $^ $(filter-out %libxenlight.so, $(LDLIBS_libxenlight)) $(LDLIBS_libxentoollog) $(LDLIBS_libxentoolcore) -lyajl $(APPEND_LDFLAGS)

libxl-save-helper: $(SAVE_HELPER_OBJS) libxenlight.so
	$(CC) $(LDFLAGS) -o $@ $(SAVE_HELPER_OBJS) $(LDLIBS_libxentoollog) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxentoolcore) $(APPEND_LDFLAGS)

testidl: testidl.o libxenlight.so
	$(CC) $(LDFLAGS) -o $@ testidl.o $(LDLIBS_libxenlight) $(LDLIBS_libxentoollog) $(LDLIBS_libxentoolcore) $(APPEND_LDFLAGS)

install:: $(LIBHEADERS) libxl-save-helper
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) libxl-save-helper $(DESTDIR)$(LIBEXEC_BIN)

uninstall::
	rm -f $(DESTDIR)$(LIBEXEC_BIN)/libxl-save-helper

clean::
	$(RM) _*.h *.o $(CLIENTS)
	$(RM) _*.c *.pyc _*.api-for-check
	$(RM) testidl.c.new testidl.c *.api-ok
	$(RM) $(TEST_PROGS) libxenlight_test.so libxl_test_*.opic
	$(RM) -r __pycache__
	$(MAKE) -C $(ACPI_PATH) ACPI_BUILD_DIR=$(CURDIR) clean
