MAJOR    = 2.0
MINOR    = 0
SONAME   = libblktap.so.$(MAJOR)

CC       = gcc

XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

INCLUDES += 

SRCS     :=
SRCS     += blktaplib.c

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

all: mk-symlinks blkdump blkcow blkimg blkcowimg blkgnbd blkcowgnbd blkaio
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
	mkdir -p $(prefix)/usr/lib
	mkdir -p $(prefix)/usr/include
	install -m0755 $(LIB) $(prefix)/usr/lib
	ln -sf libblktap.so.$(MAJOR).$(MINOR) \
                $(prefix)/usr/lib/libblktap.so.$(MAJOR)
	ln -sf libblktap.so.$(MAJOR) $(prefix)/usr/lib/libblktap.so
	install -m0644 blktaplib.h $(prefix)/usr/include

clean:
	rm -rf *.a *.so *.o *.rpm $(LIB) *~ $(DEPS) xen TAGS blkdump blkcow blkimg blkcowimg blkgnbd blkcowgnbd blkaio

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
	$(CC) -Wl,-soname -Wl,$(SONAME) -shared -o $@ $^ -L../libxutil -lxutil -lz

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

.PHONY: TAGS clean install mk-symlinks rpm
TAGS:
	etags -t $(SRCS) *.h

-include $(DEPS)
