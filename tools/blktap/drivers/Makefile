XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

INCLUDES += -I.. -I../lib -I$(XEN_INCLUDE)

IBIN         = blktapctrl tapdisk
QCOW_UTIL    = img2qcow qcow2raw qcow-create
LIBAIO_DIR   = ../../libaio/src

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -I $(XEN_LIBXC) -I $(LIBAIO_DIR)
CFLAGS   += $(INCLUDES) -I. -I../../xenstore 
CFLAGS   += -D_GNU_SOURCE

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS      = .*.d

LIBS      := -L. -L.. -L../lib
LIBS      += -L$(XEN_LIBXC)
LIBS      += -Wl,-rpath-link,$(XEN_XENSTORE)

LIBS_IMG  := $(LIBAIO_DIR)/libaio.a -lcrypto -lpthread -lz

BLK-OBJS-y  := block-aio.o
BLK-OBJS-y  += block-sync.o
BLK-OBJS-y  += block-vmdk.o
BLK-OBJS-y  += block-ram.o
BLK-OBJS-y  += block-qcow.o
BLK-OBJS-y  += aes.o
BLK-OBJS-y  += tapaio.o
BLK-OBJS-$(CONFIG_Linux) += blk_linux.c

all: $(IBIN) qcow-util

blktapctrl: blktapctrl.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS) -lblktap -lxenctrl

tapdisk: tapdisk.c $(BLK-OBJS-y) tapdisk.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS) $(LIBS_IMG)

.PHONY: qcow-util
qcow-util: img2qcow qcow2raw qcow-create

img2qcow qcow2raw qcow-create: %: $(BLK-OBJS-y)
	$(CC) $(CFLAGS) -o $* $(BLK-OBJS-y) $*.c $(LDFLAGS) $(LIBS_IMG)

install: all
	$(INSTALL_PROG) $(IBIN) $(QCOW_UTIL) $(VHD_UTIL) $(DESTDIR)$(SBINDIR)

clean:
	rm -rf *.o *~ $(DEPS) xen TAGS $(IBIN) $(LIB) $(QCOW_UTIL) $(VHD_UTIL)

.PHONY: clean install

-include $(DEPS)
