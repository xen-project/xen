XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

INCLUDES += -I.. -I../lib

IBIN         = blktapctrl tapdisk
QCOW_UTIL    = img2qcow qcow2raw qcow-create
INST_DIR     = /usr/sbin
LIBAIO_DIR   = ../../libaio/src

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -fno-strict-aliasing
CFLAGS   += -I $(XEN_LIBXC) -I $(LIBAIO_DIR)
CFLAGS   += $(INCLUDES) -I. -I../../xenstore 
CFLAGS   += -D_GNU_SOURCE

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS      = .*.d

THREADLIB := -lpthread -lz
LIBS      := -L. -L.. -L../lib
LIBS      += -L$(XEN_LIBXC)
LIBS      += -lblktap -lxenctrl
LIBS      += -lcrypto
LIBS      += -lz
LIBS      += -L$(XEN_XENSTORE) -lxenstore

AIOLIBS   := $(LIBAIO_DIR)/libaio.a

BLK-OBJS  := block-aio.o
BLK-OBJS  += block-sync.o
BLK-OBJS  += block-vmdk.o
BLK-OBJS  += block-ram.o
BLK-OBJS  += block-qcow.o
BLK-OBJS  += aes.o

all: $(IBIN) qcow-util

LINUX_ROOT := $(wildcard $(XEN_ROOT)/linux-2.6.*-xen-sparse)


blktapctrl: blktapctrl.c
	$(CC) $(CFLAGS) -o blktapctrl $(LIBS) blktapctrl.c

tapdisk: $(BLK-OBJS) tapdisk.c
	$(CC) $(CFLAGS) -o tapdisk $(BLK-OBJS) tapdisk.c \
		$(AIOLIBS) $(LIBS)

.PHONY: qcow-util
qcow-util: img2qcow qcow2raw qcow-create

img2qcow qcow2raw qcow-create: %: $(BLK-OBJS)
	$(CC) $(CFLAGS) -o $* $(BLK-OBJS) $*.c $(AIOLIBS) $(LIBS)

install: all
	$(INSTALL_PROG) $(IBIN) $(QCOW_UTIL) $(VHD_UTIL) $(DESTDIR)$(INST_DIR)

clean:
	rm -rf *.o *~ $(DEPS) xen TAGS $(IBIN) $(LIB) $(QCOW_UTIL) $(VHD_UTIL)

.PHONY: clean install

-include $(DEPS)
