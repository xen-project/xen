MAJOR    = 2.0
MINOR    = 0
SONAME   = libblktap.so.$(MAJOR)

CC       = gcc

XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

BLKTAP_INSTALL_DIR	= /usr/sbin

INSTALL         = install
INSTALL_PROG    = $(INSTALL) -m0755
INSTALL_DIR     = $(INSTALL) -d -m0755

INCLUDES += 

SRCS     :=
SRCS     += blktaplib.c

PLX_SRCS := 
PLX_SRCS += vdi.c 
PLX_SRCS += radix.c 
PLX_SRCS += snaplog.c
PLXT_SRCS := $(PLX_SRCS)
#PLXT_SRCS += blockstore-tls.c
PLXT_SRCS += blockstore.c
PLXT_SRCS += parallax-threaded.c
PLX_SRCS += blockstore.c 
VDI_SRCS := $(PLX_SRCS)
PLX_SRCS += parallax.c

VDI_TOOLS :=
VDI_TOOLS += vdi_create
VDI_TOOLS += vdi_list
VDI_TOOLS += vdi_snap
VDI_TOOLS += vdi_snap_list
VDI_TOOLS += vdi_snap_delete
VDI_TOOLS += vdi_fill
VDI_TOOLS += vdi_tree
VDI_TOOLS += vdi_validate

CFLAGS   += -Wall
CFLAGS   += -Werror
CFLAGS   += -Wno-unused
#CFLAGS   += -O3
CFLAGS   += -g3
CFLAGS   += -fno-strict-aliasing
CFLAGS   += -I $(XEN_LIBXC)
CFLAGS   += -I $(XEN_LIBXUTIL)
CFLAGS   += $(INCLUDES) -I.
CFLAGS   += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

OBJS     = $(patsubst %.c,%.o,$(SRCS))

LIB      = libblktap.so libblktap.so.$(MAJOR) libblktap.so.$(MAJOR).$(MINOR)

all: mk-symlinks blkdump blkcow blkimg blkcowimg blkgnbd blkcowgnbd $(VDI_TOOLS) parallax parallax-threaded blockstored
	$(MAKE) $(LIB)

LINUX_ROOT := $(wildcard $(XEN_ROOT)/linux-2.6.*-xen-sparse)
mk-symlinks:
	[ -e xen/linux ] || mkdir -p xen/linux
	[ -e xen/io ]    || mkdir -p xen/io
	( cd xen >/dev/null ; \
	  ln -sf ../$(XEN_ROOT)/xen/include/public/*.h . )
	( cd xen/io >/dev/null ; \
	   ln -sf ../../$(XEN_ROOT)/xen/include/public/io/*.h . )
	( cd xen/linux >/dev/null ; \
	  ln -sf ../../$(LINUX_ROOT)/include/asm-xen/linux-public/*.h . )

install: all
	$(INSTALL_DIR) -p $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DIR) -p $(DESTDIR)/usr/include
	$(INSTALL_PROG) $(LIB) $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_PROG) blktaplib.h $(DESTDIR)/usr/include
	$(INSTALL_PROG) blkdump blkcow blkimg blkcowimg blkgnbd blkcowgnbd $(DESTDIR)/$(BLKTAP_INSTALL_DIR)

clean:
	rm -rf *.a *.so *.o *.rpm $(LIB) *~ $(DEPS) xen TAGS blkdump blkcow blkimg blkcowimg blkgnbd blkcowgnbd blkaio $(VDI_TOOLS) parallax

rpm: all
	rm -rf staging
	mkdir staging
	mkdir staging/i386
	rpmbuild --define "staging$$PWD/staging" --define '_builddir.' \
		--define "_rpmdir$$PWD/staging" -bb rpm.spec
	mv staging/i386/*.rpm .
	rm -rf staging

libblktap.so:
	ln -sf libblktap.so.$(MAJOR) $@
libblktap.so.$(MAJOR):
	ln -sf libblktap.so.$(MAJOR).$(MINOR) $@
libblktap.so.$(MAJOR).$(MINOR): $(OBJS)
	$(CC) -Wl,-soname -Wl,$(SONAME) -shared -o $@ $^ -lpthread -L../libxutil -lxutil -lz

blkdump: $(LIB)
	$(CC) $(CFLAGS) -o blkdump -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -L. -l blktap blkdump.c

blkcowimg: $(LIB) blkcowimg.c blkcowlib.c blkimglib.c 
	$(CC) $(CFLAGS) -o blkcowimg -ldb -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -L. -l blktap blkcowimg.c blkimglib.c blkcowlib.c

blkcow: $(LIB) blkcow.c blkcowlib.c
	$(CC) $(CFLAGS) -o blkcow -ldb -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -L. -l blktap blkcow.c blkcowlib.c

blkimg: $(LIB) blkimg.c blkimglib.c
	$(CC) $(CFLAGS) -o blkimg  -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -L. -l blktap blkimg.c blkimglib.c

blkgnbd: $(LIB) blkgnbd.c blkgnbdlib.c
	$(CC) $(CFLAGS) -o blkgnbd -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -L. -lblktap blkgnbd.c blkgnbdlib.c libgnbd/libgnbd.a

blkcowgnbd: $(LIB) blkgnbd.c blkcowlib.c blkgnbdlib.c
	$(CC) $(CFLAGS) -o blkcowgnbd -ldb -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -L. -lblktap blkcowgnbd.c blkgnbdlib.c blkcowlib.c libgnbd/libgnbd.a

blkaio: $(LIB) blkaio.c blkaiolib.c
	$(CC) $(CFLAGS) -o blkaio -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -L. -lblktap blkaio.c blkaiolib.c -laio -lpthread

parallax: $(LIB) $(PLX_SRCS)
	$(CC) $(CFLAGS) -o parallax -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -L. -lblktap -lpthread $(PLX_SRCS) libgnbd/libgnbd.a

parallax-threaded: $(LIB) $(PLXT_SRCS)
	$(CC) $(CFLAGS) -o parallax-threaded -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -L. -lpthread -lblktap $(PLXT_SRCS) libgnbd/libgnbd.a

vdi_test: $(LIB) $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_test -DVDI_STANDALONE -lpthread $(VDI_SRCS)

vdi_list: $(LIB) vdi_list.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_list vdi_list.c -lpthread $(VDI_SRCS)

vdi_create: $(LIB) vdi_create.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_create vdi_create.c -lpthread $(VDI_SRCS)

vdi_snap: $(LIB) vdi_snap.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_snap vdi_snap.c -lpthread $(VDI_SRCS)

vdi_snap_list: $(LIB) vdi_snap_list.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_snap_list vdi_snap_list.c -lpthread $(VDI_SRCS)

vdi_snap_delete: $(LIB) vdi_snap_delete.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_snap_delete vdi_snap_delete.c -lpthread $(VDI_SRCS)

vdi_tree: $(LIB) vdi_tree.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_tree vdi_tree.c -lpthread $(VDI_SRCS)

vdi_fill: $(LIB) vdi_fill.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_fill vdi_fill.c -lpthread $(VDI_SRCS)

vdi_validate: $(LIB) vdi_validate.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_validate vdi_validate.c -lpthread $(VDI_SRCS)

blockstored: blockstored.c
	$(CC) $(CFLAGS) -g3 -o blockstored -lpthread blockstored.c
bstest: bstest.c blockstore.c
	$(CC) $(CFLAGS) -g3 -o bstest bstest.c -lpthread blockstore.c

.PHONY: TAGS clean install mk-symlinks rpm
TAGS:
	etags -t $(SRCS) *.h

-include $(DEPS)

#Random testing targets.  To be removed eventually.

rdx_cmp: $(LIB) rdx_cmp.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o rdx_cmp rdx_cmp.c $(VDI_SRCS)

bb-tls: $(LIB) blockstore-benchmark.c
	$(CC) $(CFLAGS) -o bb-tls blockstore-benchmark.c blockstore-tls.c -lpthread

bb-trans: $(LIB) blockstore-benchmark.c
	$(CC) $(CFLAGS) -o bb-trans blockstore-benchmark.c blockstore.c -lpthread

radix-test: $(LIB) radix.c blockstore.c
	$(CC) $(CFLAGS) -g3 -D RADIX_STANDALONE -o radix-test radix.c blockstore-threaded-trans.c
