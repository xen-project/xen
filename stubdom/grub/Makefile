XEN_ROOT = $(CURDIR)/../..

include $(XEN_ROOT)/Config.mk
vpath %.c ../grub-upstream

BOOT=$(OBJ_DIR)/boot-$(XEN_TARGET_ARCH).o

DEF_CPPFLAGS += -I$(XEN_ROOT)/tools/libxc -I$(XEN_ROOT)/tools/include -I.
DEF_CPPFLAGS += -I../grub-upstream/stage1
DEF_CPPFLAGS += -I../grub-upstream/stage2
DEF_CPPFLAGS += -I../grub-upstream/netboot
DEF_CPPFLAGS += -I$(XEN_ROOT)/tools/firmware/vgabios
DEF_CPPFLAGS += -DWITHOUT_LIBC_STUBS
DEF_CPPFLAGS += -DSUPPORT_NETBOOT
DEF_CPPFLAGS += -DSUPPORT_GRAPHICS
DEF_CPPFLAGS += -DSUPPORT_SERIAL
DEF_CPPFLAGS += -DPRESET_MENU_STRING='""'
DEF_CPPFLAGS += -DPACKAGE='"grubdom"' -DVERSION='"0.97"'

all: $(OBJ_DIR)/main.a

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

STAGE2_SOURCES+=fsys_xfs.c
CPPFLAGS += -DFSYS_XFS=1

STAGE2_SOURCES:=$(addprefix stage2/,$(STAGE2_SOURCES))
NETBOOT_SOURCES:=$(addprefix netboot/,$(NETBOOT_SOURCES))

$(BOOT): DEF_CPPFLAGS+=-D__ASSEMBLY__

PV_GRUB_SOURCES = kexec.c mini-os.c
PV_GRUB_SOURCES += ../polarssl-$(XEN_TARGET_ARCH)/library/sha1.o

SOURCES = $(NETBOOT_SOURCES) $(STAGE2_SOURCES) $(PV_GRUB_SOURCES)

OBJS = $(addprefix $(OBJ_DIR)/,$(SOURCES:.c=.o))

$(OBJ_DIR)/dirs:
	mkdir -p $(OBJ_DIR)/netboot $(OBJ_DIR)/stage2
	touch $@

$(OBJS): $(OBJ_DIR)/dirs

$(OBJ_DIR)/main.a: $(BOOT) $(OBJS)
	$(AR) cr $@ $^

$(OBJ_DIR)/%.o: %.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $< -o $@

$(OBJ_DIR)/%.o: %.S
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $< -o $@

clean:
	rm -fr dirs *.a *.o stage2 netboot
