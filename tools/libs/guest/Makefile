XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

ifeq ($(CONFIG_LIBXC_MINIOS),y)
# Save/restore of a domain is currently incompatible with a stubdom environment
override CONFIG_MIGRATE := n
endif

SRCS-y += xg_private.c
SRCS-y += xg_domain.c
SRCS-y += xg_suspend.c
SRCS-y += xg_resume.c
ifeq ($(CONFIG_MIGRATE),y)
SRCS-y += xg_sr_common.c
SRCS-$(CONFIG_X86) += xg_sr_common_x86.c
SRCS-$(CONFIG_X86) += xg_sr_common_x86_pv.c
SRCS-$(CONFIG_X86) += xg_sr_restore_x86_pv.c
SRCS-$(CONFIG_X86) += xg_sr_restore_x86_hvm.c
SRCS-$(CONFIG_X86) += xg_sr_save_x86_pv.c
SRCS-$(CONFIG_X86) += xg_sr_save_x86_hvm.c
SRCS-y += xg_sr_restore.c
SRCS-y += xg_sr_save.c
SRCS-y += xg_offline_page.c
else
SRCS-y += xg_nomigrate.c
endif
SRCS-y       += xg_core.c
SRCS-$(CONFIG_X86) += xg_core_x86.c
SRCS-$(CONFIG_ARM) += xg_core_arm.c

CFLAGS += -I$(XEN_libxenctrl)

vpath %.c ../../../xen/common/libelf
CFLAGS += -I../../../xen/common/libelf

ELF_SRCS-y += libelf-tools.c libelf-loader.c
ELF_SRCS-y += libelf-dominfo.c

SRCS-y += $(ELF_SRCS-y)

$(patsubst %.c,%.o,$(ELF_SRCS-y)): CFLAGS += -Wno-pointer-sign
$(patsubst %.c,%.opic,$(ELF_SRCS-y)): CFLAGS += -Wno-pointer-sign

ifeq ($(CONFIG_X86),y) # Add libx86 to the build
vpath %.c ../../../xen/lib/x86

SRCS-y                 += cpuid.c msr.c policy.c
endif

# new domain builder
SRCS-y                 += xg_dom_core.c
SRCS-y                 += xg_dom_boot.c
SRCS-y                 += xg_dom_elfloader.c
SRCS-$(CONFIG_X86)     += xg_dom_bzimageloader.c
SRCS-$(CONFIG_X86)     += xg_dom_decompress_lz4.c
SRCS-$(CONFIG_X86)     += xg_dom_hvmloader.c
SRCS-$(CONFIG_ARM)     += xg_dom_armzimageloader.c
SRCS-y                 += xg_dom_binloader.c
SRCS-y                 += xg_dom_compat_linux.c

SRCS-$(CONFIG_X86)     += xg_dom_x86.c
SRCS-$(CONFIG_X86)     += xg_cpuid_x86.c
SRCS-$(CONFIG_ARM)     += xg_dom_arm.c

ifeq ($(CONFIG_LIBXC_MINIOS),y)
SRCS-y                 += xg_dom_decompress_unsafe.c
SRCS-y                 += xg_dom_decompress_unsafe_bzip2.c
SRCS-y                 += xg_dom_decompress_unsafe_lzma.c
SRCS-y                 += xg_dom_decompress_unsafe_lzo1x.c
SRCS-y                 += xg_dom_decompress_unsafe_xz.c
SRCS-y                 += xg_dom_decompress_unsafe_zstd.c
endif

-include $(XEN_TARGET_ARCH)/Makefile

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
zlib-options =
else
zlib-options = $(ZLIB)
endif

xg_dom_bzimageloader.o: CFLAGS += $(filter -D%,$(zlib-options))
xg_dom_bzimageloader.opic: CFLAGS += $(filter -D%,$(zlib-options))

LIBHEADER := xenguest.h

NO_HEADERS_CHK := y

include $(XEN_ROOT)/tools/libs/libs.mk

libxenguest.so.$(MAJOR).$(MINOR): COMPRESSION_LIBS = $(filter -l%,$(zlib-options))
libxenguest.so.$(MAJOR).$(MINOR): APPEND_LDFLAGS += $(COMPRESSION_LIBS) -lz

genpath-target = $(call buildmakevars2header,_paths.h)
$(eval $(genpath-target))

$(LIB_OBJS) $(PIC_OBJS): _paths.h

-include $(DEPS_INCLUDE)

.PHONY: cleanlocal
cleanlocal:
	rm -f libxenguest.map
