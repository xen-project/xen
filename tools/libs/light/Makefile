XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

SRCS-y += osdeps.c
SRCS-y += libxl_paths.c
SRCS-y += libxl_bootloader.c
SRCS-y += flexarray.c
ifeq ($(CONFIG_LIBNL),y)
SRCS-y += libxl_netbuffer.c
else
SRCS-y += libxl_nonetbuffer.c
endif
ifeq ($(CONFIG_X86),y)
SRCS-y += libxl_convert_callout.c
else
SRCS-y += libxl_no_convert_callout.c
endif
SRCS-y += libxl_remus.c
SRCS-y += libxl_checkpoint_device.c
SRCS-y += libxl_remus_disk_drbd.c
ifeq ($(CONFIG_LIBNL),y)
SRCS-y += libxl_colo_restore.c
SRCS-y += libxl_colo_save.c
SRCS-y += libxl_colo_qdisk.c
SRCS-y += libxl_colo_proxy.c
SRCS-y += libxl_colo_nic.c
else
SRCS-y += libxl_no_colo.c
endif

ACPI_PATH  = $(XEN_ROOT)/tools/libacpi
DSDT_FILES-$(CONFIG_X86) = dsdt_pvh.c
ACPI_OBJS  = $(patsubst %.c,%.o,$(DSDT_FILES-y)) build.o static_tables.o
ACPI_PIC_OBJS = $(patsubst %.o,%.opic,$(ACPI_OBJS))
$(DSDT_FILES-y) build.o build.opic: acpi
vpath build.c $(ACPI_PATH)/
vpath static_tables.c $(ACPI_PATH)/

.PHONY: acpi
acpi:
	$(MAKE) -C $(ACPI_PATH) ACPI_BUILD_DIR=$(CURDIR) DSDT_FILES="$(DSDT_FILES-y)"

SRCS-$(CONFIG_X86) += $(ACPI_OBJS:.o=.c)

CFLAGS += -Wno-format-zero-length -Wmissing-declarations \
	-Wno-declaration-after-statement -Wformat-nonliteral
CFLAGS += -I.

SRCS-$(CONFIG_X86) += libxl_cpuid.c
SRCS-$(CONFIG_X86) += libxl_x86.c
SRCS-$(CONFIG_X86) += libxl_psr.c
SRCS-$(CONFIG_X86) += libxl_x86_acpi.c
SRCS-$(CONFIG_ARM) += libxl_nocpuid.c
SRCS-$(CONFIG_ARM) += libxl_arm.c
SRCS-$(CONFIG_ARM) += libxl_libfdt_compat.c
ifeq ($(CONFIG_ARM_64),y)
DSDT_FILES-y = dsdt_anycpu_arm.c
SRCS-y += libxl_arm_acpi.c
SRCS-y += $(DSDT_FILES-y)
dsdt_anycpu_arm.c:
	$(MAKE) -C $(ACPI_PATH) ACPI_BUILD_DIR=$(CURDIR) DSDT_FILES="$(DSDT_FILES-y)"
else
SRCS-$(CONFIG_ARM) += libxl_arm_no_acpi.c
endif

SRCS-OS-$(CONFIG_NetBSD) = libxl_netbsd.c
SRCS-OS-$(CONFIG_Linux) = libxl_linux.c libxl_setresuid.c
SRCS-OS-$(CONFIG_FreeBSD) = libxl_freebsd.c libxl_setresuid.c
ifeq ($(SRCS-OS-y),)
$(error Your Operating System is not supported by libxenlight, \
please check libxl_linux.c and libxl_netbsd.c to see how to get it ported)
endif
SRCS-y += $(SRCS-OS-y)

SRCS-y += libxl.c
SRCS-y += libxl_create.c
SRCS-y += libxl_dm.c
SRCS-y += libxl_pci.c
SRCS-y += libxl_dom.c
SRCS-y += libxl_exec.c
SRCS-y += libxl_xshelp.c
SRCS-y += libxl_device.c
SRCS-y += libxl_internal.c
SRCS-y += libxl_utils.c
SRCS-y += libxl_uuid.c
SRCS-y += libxl_json.c
SRCS-y += libxl_aoutils.c
SRCS-y += libxl_numa.c
SRCS-y += libxl_vnuma.c
SRCS-y += libxl_stream_read.c
SRCS-y += libxl_stream_write.c
SRCS-y += libxl_save_callout.c
SRCS-y += _libxl_save_msgs_callout.c
SRCS-y += libxl_qmp.c
SRCS-y += libxl_event.c
SRCS-y += libxl_fork.c
SRCS-y += libxl_dom_suspend.c
SRCS-y += libxl_dom_save.c
SRCS-y += libxl_usb.c
SRCS-y += libxl_vtpm.c
SRCS-y += libxl_nic.c
SRCS-y += libxl_disk.c
SRCS-y += libxl_console.c
SRCS-y += libxl_cpupool.c
SRCS-y += libxl_mem.c
SRCS-y += libxl_sched.c
SRCS-y += libxl_tmem.c
SRCS-y += libxl_9pfs.c
SRCS-y += libxl_domain.c
SRCS-y += libxl_vdispl.c
SRCS-y += libxl_pvcalls.c
SRCS-y += libxl_vsnd.c
SRCS-y += libxl_vkb.c
SRCS-y += libxl_genid.c
SRCS-y += _libxl_types.c
SRCS-y += libxl_flask.c
SRCS-y += _libxl_types_internal.c

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

AUTOINCS = $(XEN_INCLUDE)/_libxl_list.h _paths.h _libxl_save_msgs_callout.h _libxl_save_msgs_helper.h
AUTOSRCS = _libxl_save_msgs_callout.c _libxl_save_msgs_helper.c

CLIENTS = testidl libxl-save-helper

SAVE_HELPER_OBJS = libxl_save_helper.o _libxl_save_msgs_helper.o

LIBHEADER := libxl.h libxl_event.h libxl_json.h _libxl_types.h _libxl_types_json.h _libxl_list.h libxl_utils.h libxl_uuid.h

NO_HEADERS_CHK := y

include $(XEN_ROOT)/tools/libs/libs.mk

LDUSELIBS-y += $(PTYFUNCS_LIBS)
LDUSELIBS-$(CONFIG_LIBNL) += $(LIBNL3_LIBS)
LDUSELIBS-$(CONFIG_Linux) += -luuid
LDUSELIBS-$(CONFIG_Linux) += -lrt
LDUSELIBS-$(CONFIG_ARM) += -lfdt
LDUSELIBS-y += $(PTHREAD_LIBS)
LDUSELIBS-y += -lyajl
LDUSELIBS += $(LDUSELIBS-y)

$(LIB_OBJS) $(PIC_OBJS) $(LIBXL_TEST_OBJS): CFLAGS += $(CFLAGS_LIBXL) -include $(XEN_ROOT)/tools/config.h
$(ACPI_OBJS) $(ACPI_PIC_OBJS): CFLAGS += -I. -DLIBACPI_STDUTILS=\"$(CURDIR)/libxl_x86_acpi.h\"
$(TEST_PROG_OBJS) _libxl.api-for-check: CFLAGS += $(CFLAGS_libxentoollog) $(CFLAGS_libxentoolcore)
libxl_dom.o libxl_dom.opic: CFLAGS += -I$(XEN_ROOT)/tools  # include libacpi/x86.h
libxl_x86_acpi.o libxl_x86_acpi.opic: CFLAGS += -I$(XEN_ROOT)/tools
$(SAVE_HELPER_OBJS): CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_libxenevtchn) $(CFLAGS_libxenguest)

testidl.o: CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_libxenlight)
testidl.c: libxl_types.idl gentest.py $(XEN_INCLUDE)/libxl.h $(AUTOINCS)
	$(PYTHON) gentest.py libxl_types.idl testidl.c.new
	mv testidl.c.new testidl.c

build: $(CLIENTS) $(TEST_PROGS) $(AUTOSRCS) $(AUTOINCS)

$(LIB_OBJS) $(PIC_OBJS) $(SAVE_HELPER_OBJS) $(LIBXL_TEST_OBJS) $(TEST_PROG_OBJS): $(AUTOINCS) libxl.api-ok

genpath-target = $(call buildmakevars2header,_paths.h)
$(eval $(genpath-target))

libxl.api-ok: check-libxl-api-rules _libxl.api-for-check
	$(PERL) $^
	touch $@

_libxl.api-for-check: $(XEN_INCLUDE)/libxl.h $(AUTOINCS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_libxl.o) -c -E $< $(APPEND_CFLAGS) \
		-DLIBXL_EXTERNAL_CALLERS_ONLY=LIBXL_EXTERNAL_CALLERS_ONLY \
		>$@.new
	mv -f $@.new $@

$(XEN_INCLUDE)/_libxl_list.h: $(XEN_INCLUDE)/xen-external/bsd-sys-queue-h-seddery $(XEN_INCLUDE)/xen-external/bsd-sys-queue.h
	$(PERL) $^ --prefix=libxl >$(notdir $@).new
	$(call move-if-changed,$(notdir $@).new,$@)

_libxl_save_msgs_helper.c _libxl_save_msgs_callout.c \
_libxl_save_msgs_helper.h _libxl_save_msgs_callout.h: \
		libxl_save_msgs_gen.pl
	$(PERL) -w $< $@ >$@.new
	$(call move-if-changed,$@.new,$@)

$(XEN_INCLUDE)/libxl.h: $(XEN_INCLUDE)/_libxl_types.h $(XEN_INCLUDE)/_libxl_list.h
$(XEN_INCLUDE)/libxl_json.h: $(XEN_INCLUDE)/_libxl_types_json.h
libxl_internal.h: _libxl_types_internal.h _libxl_types_private.h _libxl_types_internal_private.h _paths.h
libxl_internal_json.h: _libxl_types_internal_json.h
xl.h: _paths.h

$(LIB_OBJS) $(PIC_OBJS) $(LIBXL_TEST_OBJS) $(TEST_PROG_OBJS) $(SAVE_HELPER_OBJS): $(XEN_INCLUDE)/libxl.h
$(LIB_OBJS) $(PIC_OBJS) $(LIBXL_TEST_OBJS): libxl_internal.h

_libxl_type%.h _libxl_type%_json.h _libxl_type%_private.h _libxl_type%.c: libxl_type%.idl gentypes.py idl.py
	$(eval stem = $(notdir $*))
	$(PYTHON) gentypes.py libxl_type$(stem).idl __libxl_type$(stem).h __libxl_type$(stem)_private.h \
		__libxl_type$(stem)_json.h  __libxl_type$(stem).c
	$(call move-if-changed,__libxl_type$(stem).h,_libxl_type$(stem).h)
	$(call move-if-changed,__libxl_type$(stem)_private.h,_libxl_type$(stem)_private.h)
	$(call move-if-changed,__libxl_type$(stem)_json.h,_libxl_type$(stem)_json.h)
	$(call move-if-changed,__libxl_type$(stem).c,_libxl_type$(stem).c)

$(XEN_INCLUDE)/_%.h: _%.h
	$(call move-if-changed,_$*.h,$(XEN_INCLUDE)/_$*.h)

libxenlight_test.so: $(PIC_OBJS) $(LIBXL_TEST_OBJS)
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenlight.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(LDUSELIBS) $(APPEND_LDFLAGS)

test_%: test_%.o test_common.o libxenlight_test.so
	$(CC) $(LDFLAGS) -o $@ $^ $(filter-out %libxenlight.so, $(LDLIBS_libxenlight)) $(LDLIBS_libxentoollog) $(LDLIBS_libxentoolcore) -lyajl $(APPEND_LDFLAGS)

libxl-save-helper: $(SAVE_HELPER_OBJS) libxenlight.so
	$(CC) $(LDFLAGS) -o $@ $(SAVE_HELPER_OBJS) $(LDLIBS_libxentoollog) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxentoolcore) $(APPEND_LDFLAGS)

testidl: testidl.o libxenlight.so
	$(CC) $(LDFLAGS) -o $@ testidl.o $(LDLIBS_libxenlight) $(LDLIBS_libxentoollog) $(LDLIBS_libxentoolcore) $(APPEND_LDFLAGS)

install: installlocal $(LIBHEADERS)

.PHONY: installlocal
installlocal: libxl-save-helper
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) libxl-save-helper $(DESTDIR)$(LIBEXEC_BIN)

uninstall: uninstalllocal

.PHONY: uninstalllocal
uninstalllocal:
	rm -f $(DESTDIR)$(LIBEXEC_BIN)/libxl-save-helper

clean: cleanlocal

.PHONY: cleanlocal
cleanlocal:
	$(RM) -f _*.h *.o $(CLIENTS)
	$(RM) -f _*.c *.pyc _paths.*.tmp _*.api-for-check
	$(RM) -f testidl.c.new testidl.c *.api-ok
	$(RM) -f $(TEST_PROGS)
	$(RM) -rf __pycache__
	$(RM) -f libxenlight.map
	$(RM) -f $(AUTOSRCS) $(AUTOINCS)
	$(MAKE) -C $(ACPI_PATH) ACPI_BUILD_DIR=$(CURDIR) clean
