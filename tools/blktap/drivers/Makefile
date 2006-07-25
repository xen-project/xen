XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

INCLUDES += -I.. -I../lib

INSTALL      = install
INSTALL_PROG = $(INSTALL) -m0755
IBIN         = blktapctrl tapdisk
QCOW_UTIL    = img2qcow qcow2raw qcow-create
INSTALL_DIR  = /usr/sbin
LIBAIO_DIR   = ../../libaio/src

CFLAGS   += -fPIC
CFLAGS   += -Wall
CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -g3
CFLAGS   += -fno-strict-aliasing
CFLAGS   += -I $(XEN_LIBXC) -I $(LIBAIO_DIR)
CFLAGS   += $(INCLUDES) -I. -I../../xenstore 
CFLAGS   += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CFLAGS   += -D_GNU_SOURCE

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

THREADLIB := -lpthread -lz
LIBS      := -L. -L.. -L../lib
LIBS      += -L$(XEN_LIBXC)
LIBS      += -lblktap
LIBS      += -lcrypto
LIBS      += -lz
LIBS      += -L$(XEN_XENSTORE) -lxenstore

AIOLIBS   := -L $(LIBAIO_DIR)
AIOLIBS   += -laio
AIOLIBS   += -static

BLK-OBJS  := block-aio.o 
BLK-OBJS  += block-sync.o 
BLK-OBJS  += block-vmdk.o
BLK-OBJS  += block-ram.o 
BLK-OBJS  += block-qcow.o
BLK-OBJS  += aes.o

all: $(IBIN) qcow-util

LINUX_ROOT := $(wildcard $(XEN_ROOT)/linux-2.6.*-xen-sparse)


blktapctrl: 
	$(CC) $(CFLAGS) -o blktapctrl $(LIBS) blktapctrl.c

tapdisk: $(BLK-OBJS)
	$(CC) $(CFLAGS) -o tapdisk $(BLK-OBJS) tapdisk.c \
		$(AIOLIBS) $(LIBS)


qcow-util: $(BLK-OBJS)
	$(CC) $(CFLAGS) -o img2qcow $(BLK-OBJS) img2qcow.c \
		$(AIOLIBS)  $(LIBS)
	$(CC) $(CFLAGS) -o qcow2raw $(BLK-OBJS) qcow2raw.c  \
		$(AIOLIBS)  $(LIBS)
	$(CC) $(CFLAGS) -o qcow-create $(BLK-OBJS) qcow-create.c  \
		$(AIOLIBS)  $(LIBS)

install: all
	$(INSTALL_PROG) $(IBIN) $(QCOW_UTIL) $(DESTDIR)$(INSTALL_DIR)

clean:
	rm -rf *.o *~ $(DEPS) xen TAGS $(IBIN) $(LIB) $(QCOW_UTIL)

.PHONY: clean install

-include $(DEPS)
