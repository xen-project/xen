XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 4.5
MINOR    = 0

CTRL_SRCS-y       :=
CTRL_SRCS-y       += xc_core.c
CTRL_SRCS-$(CONFIG_X86) += xc_core_x86.c
CTRL_SRCS-$(CONFIG_ARM) += xc_core_arm.c
CTRL_SRCS-y       += xc_cpupool.c
CTRL_SRCS-y       += xc_domain.c
CTRL_SRCS-y       += xc_evtchn.c
CTRL_SRCS-y       += xc_gnttab.c
CTRL_SRCS-y       += xc_misc.c
CTRL_SRCS-y       += xc_flask.c
CTRL_SRCS-y       += xc_physdev.c
CTRL_SRCS-y       += xc_private.c
CTRL_SRCS-y       += xc_sedf.c
CTRL_SRCS-y       += xc_csched.c
CTRL_SRCS-y       += xc_csched2.c
CTRL_SRCS-y       += xc_arinc653.c
CTRL_SRCS-y       += xc_rt.c
CTRL_SRCS-y       += xc_tbuf.c
CTRL_SRCS-y       += xc_pm.c
CTRL_SRCS-y       += xc_cpu_hotplug.c
CTRL_SRCS-y       += xc_resume.c
CTRL_SRCS-y       += xc_tmem.c
CTRL_SRCS-y       += xc_mem_event.c
CTRL_SRCS-y       += xc_mem_paging.c
CTRL_SRCS-y       += xc_mem_access.c
CTRL_SRCS-y       += xc_memshr.c
CTRL_SRCS-y       += xc_hcall_buf.c
CTRL_SRCS-y       += xc_foreign_memory.c
CTRL_SRCS-y       += xc_kexec.c
CTRL_SRCS-y       += xtl_core.c
CTRL_SRCS-y       += xtl_logger_stdio.c
CTRL_SRCS-y       += xc_resource.c
CTRL_SRCS-$(CONFIG_X86) += xc_psr.c
CTRL_SRCS-$(CONFIG_X86) += xc_pagetab.c
CTRL_SRCS-$(CONFIG_Linux) += xc_linux.c xc_linux_osdep.c
CTRL_SRCS-$(CONFIG_FreeBSD) += xc_freebsd.c xc_freebsd_osdep.c
CTRL_SRCS-$(CONFIG_SunOS) += xc_solaris.c
CTRL_SRCS-$(CONFIG_NetBSD) += xc_netbsd.c
CTRL_SRCS-$(CONFIG_MiniOS) += xc_minios.c

GUEST_SRCS-y :=
GUEST_SRCS-y += xg_private.c xc_suspend.c
ifeq ($(CONFIG_MIGRATE),y)
GUEST_SRCS-y += xc_domain_restore.c xc_domain_save.c
GUEST_SRCS-y += xc_offline_page.c xc_compression.c
else
GUEST_SRCS-y += xc_nomigrate.c
endif

vpath %.c ../../xen/common/libelf
CFLAGS += -I../../xen/common/libelf

ELF_SRCS-y += libelf-tools.c libelf-loader.c
ELF_SRCS-y += libelf-dominfo.c

GUEST_SRCS-y += $(ELF_SRCS-y)

$(patsubst %.c,%.o,$(ELF_SRCS-y)): CFLAGS += -Wno-pointer-sign
$(patsubst %.c,%.opic,$(ELF_SRCS-y)): CFLAGS += -Wno-pointer-sign

# new domain builder
GUEST_SRCS-y                 += xc_dom_core.c xc_dom_boot.c
GUEST_SRCS-y                 += xc_dom_elfloader.c
GUEST_SRCS-$(CONFIG_X86)     += xc_dom_bzimageloader.c
GUEST_SRCS-$(CONFIG_X86)     += xc_dom_decompress_lz4.c
GUEST_SRCS-$(CONFIG_ARM)     += xc_dom_armzimageloader.c
GUEST_SRCS-y                 += xc_dom_binloader.c
GUEST_SRCS-y                 += xc_dom_compat_linux.c

GUEST_SRCS-$(CONFIG_X86)     += xc_dom_x86.c
GUEST_SRCS-$(CONFIG_X86)     += xc_cpuid_x86.c
GUEST_SRCS-$(CONFIG_X86)     += xc_hvm_build_x86.c
GUEST_SRCS-$(CONFIG_ARM)     += xc_dom_arm.c
GUEST_SRCS-$(CONFIG_ARM)     += xc_hvm_build_arm.c

ifeq ($(CONFIG_LIBXC_MINIOS),y)
GUEST_SRCS-y                 += xc_dom_decompress_unsafe.c
GUEST_SRCS-y                 += xc_dom_decompress_unsafe_bzip2.c
GUEST_SRCS-y                 += xc_dom_decompress_unsafe_lzma.c
GUEST_SRCS-y                 += xc_dom_decompress_unsafe_lzo1x.c
GUEST_SRCS-y                 += xc_dom_decompress_unsafe_xz.c
endif

OSDEP_SRCS-y                 += xenctrl_osdep_ENOSYS.c

-include $(XEN_TARGET_ARCH)/Makefile

CFLAGS   += -Werror -Wmissing-prototypes
CFLAGS   += -I. -I./include $(CFLAGS_xeninclude)

# Needed for posix_fadvise64() in xc_linux.c
CFLAGS-$(CONFIG_Linux) += -D_GNU_SOURCE

CFLAGS	+= $(PTHREAD_CFLAGS)

CTRL_LIB_OBJS := $(patsubst %.c,%.o,$(CTRL_SRCS-y))
CTRL_PIC_OBJS := $(patsubst %.c,%.opic,$(CTRL_SRCS-y))

GUEST_LIB_OBJS := $(patsubst %.c,%.o,$(GUEST_SRCS-y))
GUEST_PIC_OBJS := $(patsubst %.c,%.opic,$(GUEST_SRCS-y))

OSDEP_LIB_OBJS := $(patsubst %.c,%.o,$(OSDEP_SRCS-y))
OSDEP_PIC_OBJS := $(patsubst %.c,%.opic,$(OSDEP_SRCS-y))

$(CTRL_LIB_OBJS) $(GUEST_LIB_OBJS) $(OSDEP_LIB_OBJS) \
$(CTRL_PIC_OBJS) $(GUEST_PIC_OBJS) $(OSDEP_PIC_OBJS) : CFLAGS += -include $(XEN_ROOT)/tools/config.h

LIB := libxenctrl.a
ifneq ($(nosharedlibs),y)
LIB += libxenctrl.so libxenctrl.so.$(MAJOR) libxenctrl.so.$(MAJOR).$(MINOR)
endif

LIB += libxenguest.a
ifneq ($(nosharedlibs),y)
LIB += libxenguest.so libxenguest.so.$(MAJOR) libxenguest.so.$(MAJOR).$(MINOR)
endif

ifneq ($(nosharedlibs),y)
LIB += xenctrl_osdep_ENOSYS.so
endif

genpath-target = $(call buildmakevars2header,_paths.h)
$(eval $(genpath-target))

xc_private.h: _paths.h

$(CTRL_LIB_OBJS) $(GUEST_LIB_OBJS) $(OSDEP_LIB_OBJS) \
$(CTRL_PIC_OBJS) $(GUEST_PIC_OBJS) $(OSDEP_PIC_OBJS): xc_private.h

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) libs

.PHONY: libs
libs: $(LIB)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_DIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_SHLIB) libxenctrl.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_DATA) libxenctrl.a $(DESTDIR)$(LIBDIR)
	$(SYMLINK_SHLIB) libxenctrl.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libxenctrl.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxenctrl.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libxenctrl.so
	$(INSTALL_DATA) include/xenctrl.h include/xenctrlosdep.h include/xentoollog.h $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_SHLIB) libxenguest.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_DATA) libxenguest.a $(DESTDIR)$(LIBDIR)
	$(SYMLINK_SHLIB) libxenguest.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libxenguest.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxenguest.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libxenguest.so
	$(INSTALL_DATA) include/xenguest.h $(DESTDIR)$(INCLUDEDIR)

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS) \
            _paths.h \
            $(CTRL_LIB_OBJS) $(CTRL_PIC_OBJS) \
            $(GUEST_LIB_OBJS) $(GUEST_PIC_OBJS) \
            $(OSDEP_LIB_OBJS) $(OSDEP_PIC_OBJS)

.PHONY: rpm
rpm: build
	rm -rf staging
	mkdir staging
	mkdir staging/i386
	rpmbuild --define "staging$$PWD/staging" --define '_builddir.' \
		--define "_rpmdir$$PWD/staging" -bb rpm.spec
	mv staging/i386/*.rpm .
	rm -rf staging

# libxenctrl

libxenctrl.a: $(CTRL_LIB_OBJS)
	$(AR) rc $@ $^

libxenctrl.so: libxenctrl.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxenctrl.so.$(MAJOR): libxenctrl.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxenctrl.so.$(MAJOR).$(MINOR): $(CTRL_PIC_OBJS)
	$(CC) $(LDFLAGS) $(PTHREAD_LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenctrl.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(DLOPEN_LIBS) $(PTHREAD_LIBS) $(APPEND_LDFLAGS)

# libxenguest

libxenguest.a: $(GUEST_LIB_OBJS)
	$(AR) rc $@ $^

libxenguest.so: libxenguest.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxenguest.so.$(MAJOR): libxenguest.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

ifeq ($(CONFIG_MiniOS),y)
zlib-options =
else
zlib-options = $(ZLIB)
endif

xc_dom_bzimageloader.o: CFLAGS += $(call zlib-options,D)
xc_dom_bzimageloader.opic: CFLAGS += $(call zlib-options,D)

libxenguest.so.$(MAJOR).$(MINOR): COMPRESSION_LIBS = $(call zlib-options,l)
libxenguest.so.$(MAJOR).$(MINOR): $(GUEST_PIC_OBJS) libxenctrl.so
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenguest.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(GUEST_PIC_OBJS) $(COMPRESSION_LIBS) -lz $(LDLIBS_libxenctrl) $(PTHREAD_LIBS) $(APPEND_LDFLAGS)

xenctrl_osdep_ENOSYS.so: $(OSDEP_PIC_OBJS) libxenctrl.so
	$(CC) $(LDFLAGS) $(SHLIB_LDFLAGS) -o $@ $(OSDEP_PIC_OBJS) $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

-include $(DEPS)

