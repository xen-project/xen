XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

ifeq ($(CONFIG_LIBXC_MINIOS),y)
# Save/restore of a domain is currently incompatible with a stubdom environment
override CONFIG_MIGRATE := n
endif

OBJS-y += xg_private.o
OBJS-y += xg_domain.o
OBJS-y += xg_suspend.o
OBJS-y += xg_resume.o
ifeq ($(CONFIG_MIGRATE),y)
OBJS-y += xg_sr_common.o
OBJS-$(CONFIG_X86) += xg_sr_common_x86.o
OBJS-$(CONFIG_X86) += xg_sr_common_x86_pv.o
OBJS-$(CONFIG_X86) += xg_sr_restore_x86_pv.o
OBJS-$(CONFIG_X86) += xg_sr_restore_x86_hvm.o
OBJS-$(CONFIG_X86) += xg_sr_save_x86_pv.o
OBJS-$(CONFIG_X86) += xg_sr_save_x86_hvm.o
OBJS-y += xg_sr_restore.o
OBJS-y += xg_sr_save.o
OBJS-y += xg_offline_page.o
else
OBJS-y += xg_nomigrate.o
endif
OBJS-y       += xg_core.o
OBJS-$(CONFIG_X86) += xg_core_x86.o
OBJS-$(CONFIG_ARM) += xg_core_arm.o

CFLAGS += -I$(XEN_libxenctrl)

vpath %.c ../../../xen/common/libelf
CFLAGS += -I../../../xen/common/libelf

LIBELF_OBJS += libelf-tools.o libelf-loader.o
LIBELF_OBJS += libelf-dominfo.o

OBJS-y += $(LIBELF_OBJS)

$(LIBELF_OBJS) $(LIBELF_OBJS:.o=.opic): CFLAGS += -Wno-pointer-sign

ifeq ($(CONFIG_X86),y) # Add libx86 to the build
vpath %.c ../../../xen/lib/x86

OBJS-y                 += cpuid.o msr.o policy.o
endif

# new domain builder
OBJS-y                 += xg_dom_core.o
OBJS-y                 += xg_dom_boot.o
OBJS-y                 += xg_dom_elfloader.o
OBJS-$(CONFIG_X86)     += xg_dom_bzimageloader.o
OBJS-$(CONFIG_X86)     += xg_dom_decompress_lz4.o
OBJS-$(CONFIG_X86)     += xg_dom_hvmloader.o
OBJS-$(CONFIG_ARM)     += xg_dom_armzimageloader.o
OBJS-y                 += xg_dom_binloader.o
OBJS-y                 += xg_dom_compat_linux.o

OBJS-$(CONFIG_X86)     += xg_dom_x86.o
OBJS-$(CONFIG_X86)     += xg_cpuid_x86.o
OBJS-$(CONFIG_ARM)     += xg_dom_arm.o

ifeq ($(CONFIG_LIBXC_MINIOS),y)
OBJS-y                 += xg_dom_decompress_unsafe.o
OBJS-y                 += xg_dom_decompress_unsafe_bzip2.o
OBJS-y                 += xg_dom_decompress_unsafe_lzma.o
OBJS-y                 += xg_dom_decompress_unsafe_lzo1x.o
OBJS-y                 += xg_dom_decompress_unsafe_xz.o
OBJS-y                 += xg_dom_decompress_unsafe_zstd.o
endif

CFLAGS   += -Werror -Wmissing-prototypes
CFLAGS   += -I. -I./include $(CFLAGS_xeninclude)
CFLAGS   += -D__XEN_TOOLS__
CFLAGS   += -include $(XEN_ROOT)/tools/config.h

# Needed for posix_fadvise64() in xc_linux.c
CFLAGS-$(CONFIG_Linux) += -D_GNU_SOURCE

CFLAGS	+= $(PTHREAD_CFLAGS)
CFLAGS	+= $(CFLAGS_libxentoollog)
CFLAGS	+= $(CFLAGS_libxenevtchn)
CFLAGS	+= $(CFLAGS_libxendevicemodel)

# libxenguest includes xc_private.h, so needs this despite not using
# this functionality directly.
CFLAGS += $(CFLAGS_libxencall) $(CFLAGS_libxenforeignmemory)

ifeq ($(CONFIG_MiniOS),y)
ZLIB_CFLAGS :=
ZLIB_LIBS :=
endif

xg_dom_bzimageloader.o: CFLAGS += $(ZLIB_CFLAGS)
xg_dom_bzimageloader.opic: CFLAGS += $(ZLIB_CFLAGS)

LIBHEADER := xenguest.h

NO_HEADERS_CHK := y

include $(XEN_ROOT)/tools/libs/libs.mk

libxenguest.so.$(MAJOR).$(MINOR): LDLIBS += $(ZLIB_LIBS) -lz

clean::
	rm -f libxenguest.map
