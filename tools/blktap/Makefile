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

LIBS     := -lpthread -lz

SRCS     :=
SRCS     += blktaplib.c

PLX_SRCS := 
PLX_SRCS += vdi.c 
PLX_SRCS += radix.c 
PLX_SRCS += snaplog.c
PLX_SRCS += blockstore.c 
PLX_SRCS += block-async.c
PLX_SRCS += requests-async.c
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
CFLAGS   += $(INCLUDES) -I.
CFLAGS   += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

OBJS     = $(patsubst %.c,%.o,$(SRCS))
IBINS    = blkdump parallax $(VDI_TOOLS)

LIB      = libblktap.so libblktap.so.$(MAJOR) libblktap.so.$(MAJOR).$(MINOR)

all: mk-symlinks blkdump $(VDI_TOOLS) parallax blockstored
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
	$(INSTALL_PROG) $(IBINS) $(DESTDIR)/$(BLKTAP_INSTALL_DIR)

clean:
	rm -rf *.a *.so *.o *.rpm $(LIB) *~ $(DEPS) xen TAGS blkdump $(VDI_TOOLS) parallax

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
	$(CC) -Wl,-soname -Wl,$(SONAME) -shared -o $@ $^ $(LIBS)

blkdump: $(LIB)
	$(CC) $(CFLAGS) -o blkdump -L$(XEN_LIBXC) -L. -l blktap blkdump.c

parallax: $(LIB) $(PLX_SRCS)
	$(CC) $(CFLAGS) -o parallax -L$(XEN_LIBXC) -L. -lblktap $(LIBS) $(PLX_SRCS) 

vdi_list: $(LIB) vdi_list.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_list vdi_list.c $(LIBS) $(VDI_SRCS)

vdi_create: $(LIB) vdi_create.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_create vdi_create.c $(LIBS) $(VDI_SRCS)

vdi_snap: $(LIB) vdi_snap.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_snap vdi_snap.c $(LIBS) $(VDI_SRCS)

vdi_snap_list: $(LIB) vdi_snap_list.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_snap_list vdi_snap_list.c $(LIBS) $(VDI_SRCS)

vdi_snap_delete: $(LIB) vdi_snap_delete.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_snap_delete vdi_snap_delete.c $(LIBS) $(VDI_SRCS)

vdi_tree: $(LIB) vdi_tree.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_tree vdi_tree.c $(LIBS) $(VDI_SRCS)

vdi_fill: $(LIB) vdi_fill.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_fill vdi_fill.c $(LIBS) $(VDI_SRCS)

vdi_validate: $(LIB) vdi_validate.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_validate vdi_validate.c $(LIBS) $(VDI_SRCS)

vdi_unittest: $(LIB) vdi_unittest.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -g3 -o vdi_unittest vdi_unittest.c $(LIBS) $(VDI_SRCS)

blockstored: blockstored.c
	$(CC) $(CFLAGS) -g3 -o blockstored $(LIBS) blockstored.c
bstest: bstest.c blockstore.c
	$(CC) $(CFLAGS) -g3 -o bstest bstest.c $(LIBS) blockstore.c

.PHONY: TAGS clean install mk-symlinks rpm
TAGS:
	etags -t $(SRCS) *.h

-include $(DEPS)

