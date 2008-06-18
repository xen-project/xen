XEN_ROOT = ../..

include $(XEN_ROOT)/Config.mk
vpath %.c ../grub-cvs

BOOT=boot-$(XEN_TARGET_ARCH).o

DEF_CPPFLAGS += -I$(XEN_ROOT)/tools/libxc -I.
DEF_CPPFLAGS += -I../grub-cvs/stage1
DEF_CPPFLAGS += -I../grub-cvs/stage2
DEF_CPPFLAGS += -I../grub-cvs/netboot
DEF_CPPFLAGS += -I$(XEN_ROOT)/tools/firmware/vgabios
DEF_CPPFLAGS += -DWITHOUT_LIBC_STUBS
DEF_CPPFLAGS += -DSUPPORT_NETBOOT
DEF_CPPFLAGS += -DSUPPORT_GRAPHICS
DEF_CPPFLAGS += -DSUPPORT_SERIAL
DEF_CPPFLAGS += -DPRESET_MENU_STRING='""'
DEF_CPPFLAGS += -DPACKAGE='"grubdom"' -DVERSION='"0.97"'

all: main.a

STAGE2_SOURCES=builtins.c char_io.c cmdline.c common.c console.c disk_io.c graphics.c gunzip.c md5.c serial.c stage2.c terminfo.c tparm.c

NETBOOT_SOURCES=fsys_tftp.c main.c misc.c
CPPFLAGS += -DFSYS_TFTP=1

STAGE2_SOURCES+=fsys_ext2fs.c
CPPFLAGS += -DFSYS_EXT2FS=1

STAGE2_SOURCES+=fsys_fat.c
CPPFLAGS += -DFSYS_FAT=1

STAGE2_SOURCES+=fsys_ffs.c
CPPFLAGS += -DFSYS_FFS=1

STAGE2_SOURCES+=fsys_iso9660.c
CPPFLAGS += -DFSYS_ISO9660=1

STAGE2_SOURCES+=fsys_jfs.c
CPPFLAGS += -DFSYS_JFS=1

STAGE2_SOURCES+=fsys_minix.c
CPPFLAGS += -DFSYS_MINIX=1

STAGE2_SOURCES+=fsys_reiserfs.c
CPPFLAGS += -DFSYS_REISERFS=1

STAGE2_SOURCES+=fsys_ufs2.c
CPPFLAGS += -DFSYS_UFS2=1

STAGE2_SOURCES+=fsys_vstafs.c
CPPFLAGS += -DFSYS_VSTAFS=1

ifeq (0,1)
STAGE2_SOURCES+=fsys_xfs.c
CPPFLAGS += -DFSYS_XFS=1
endif

STAGE2_SOURCES:=$(addprefix stage2/,$(STAGE2_SOURCES))
NETBOOT_SOURCES:=$(addprefix netboot/,$(NETBOOT_SOURCES))

$(BOOT): DEF_CPPFLAGS+=-D__ASSEMBLY__

OBJS = $(NETBOOT_SOURCES:.c=.o) $(STAGE2_SOURCES:.c=.o) kexec.o mini-os.o

dirs:
	mkdir -p netboot stage2
	touch $@

$(OBJS): dirs

main.a: $(BOOT) $(OBJS)
	$(AR) cr $@ $^

clean:
	rm -fr dirs *.a *.o stage2 netboot
