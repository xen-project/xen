XEN_ROOT=../../../
BLKTAP_ROOT= ..
include $(XEN_ROOT)/tools/Rules.mk

LIBVHDDIR  = $(BLKTAP_ROOT)/vhd/lib

IBIN       = tapdisk2 td-util tapdisk-client tapdisk-stream tapdisk-diff
QCOW_UTIL  = img2qcow qcow-create qcow2raw
LOCK_UTIL  = lock-util
INST_DIR   = $(SBINDIR)

CFLAGS    += -Werror -g -O0
CFLAGS    += -Wno-unused
CFLAGS    += -fno-strict-aliasing
CFLAGS    += -I../lib -I../../libxc
CFLAGS    += -I../include -I../../include
CFLAGS    += -I $(LIBAIO_DIR)
CFLAGS    += -D_GNU_SOURCE
CFLAGS    += -DUSE_NFS_LOCKS

ifeq ($(CONFIG_X86_64),y)
CFLAGS            += -fPIC
endif

LIBS      += -lrt -lz

ifeq ($(CONFIG_Linux),y)
ifeq ($(shell . ./check_gcrypt $(CC)),yes)
CFLAGS += -DUSE_GCRYPT
CRYPT_LIB += -lgcrypt
else
CRYPT_LIB += -lcrypto
$(warning === libgcrypt not installed: falling back to libcrypto ===)
endif
else
CRYPT_LIB += -lcrypto
endif

LDFLAGS_img := $(CRYPT_LIB) -lpthread -lz -lm

LIBS += -L$(LIBVHDDIR) -lvhd

ifeq ($(CONFIG_Linux),y)
LIBS += -luuid
endif

REMUS-OBJS  := block-remus.o
REMUS-OBJS  += hashtable.o
REMUS-OBJS  += hashtable_itr.o
REMUS-OBJS  += hashtable_utility.o

$(REMUS-OBJS): CFLAGS += -fgnu89-inline -I$(XEN_XENSTORE)


LIBAIO_DIR = $(XEN_ROOT)/tools/libaio/src
tapdisk2 tapdisk-stream tapdisk-diff $(QCOW_UTIL): AIOLIBS := $(LIBAIO_DIR)/libaio.a
tapdisk-client tapdisk-stream tapdisk-diff $(QCOW_UTIL): CFLAGS  += -I$(LIBAIO_DIR) -I$(XEN_LIBXC)

ifeq ($(VHD_STATIC),y)
td-util: CFLAGS += -static
endif

PORTABLE-OBJS-y :=
PORTABLE-OBJS-$(CONFIG_Linux)  += blk_linux.o
PORTABLE-OBJS-$(CONFIG_NetBSD) += blk_netbsd.o

TAP-OBJS-y  := scheduler.o
TAP-OBJS-y  += tapdisk-ipc.o
TAP-OBJS-y  += tapdisk-vbd.o
TAP-OBJS-y  += tapdisk-image.o
TAP-OBJS-y  += tapdisk-driver.o
TAP-OBJS-y  += tapdisk-interface.o
TAP-OBJS-y  += tapdisk-server.o
TAP-OBJS-y  += tapdisk-queue.o
TAP-OBJS-y  += tapdisk-filter.o
TAP-OBJS-y  += tapdisk-log.o
TAP-OBJS-y  += tapdisk-utils.o
TAP-OBJS-y  += io-optimize.o
TAP-OBJS-y  += lock.o
TAP-OBJS-y  += $(PORTABLE-OBJS-y)

MISC-OBJS-y := atomicio.o

BLK-OBJS-y  := block-aio.o
BLK-OBJS-y  += block-ram.o
BLK-OBJS-y  += block-cache.o
BLK-OBJS-y  += block-vhd.o
BLK-OBJS-y  += block-log.o
BLK-OBJS-y  += block-qcow.o
BLK-OBJS-y  += aes.o
BLK-OBJS-y  += $(PORTABLE-OBJS-y)
BLK-OBJS-y  += $(REMUS-OBJS)

all: $(IBIN) lock-util qcow-util


tapdisk2: $(TAP-OBJS-y) $(BLK-OBJS-y) $(MISC-OBJS-y) tapdisk2.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS) $(AIOLIBS) $(LDFLAGS_img)

tapdisk-client: tapdisk-client.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)  $(LDFLAGS_img)

tapdisk-stream tapdisk-diff: %: %.o $(TAP-OBJS-y) $(BLK-OBJS-y)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS) $(AIOLIBS)  $(LDFLAGS_img)

td-util: td.o tapdisk-utils.o tapdisk-log.o $(PORTABLE-OBJS-y)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)  $(LDFLAGS_img)

lock-util: lock.c
	$(CC) $(CFLAGS) -DUTIL -o lock-util lock.c $(LDFLAGS) $(LIBS)

.PHONY: qcow-util
qcow-util: img2qcow qcow2raw qcow-create

img2qcow qcow2raw qcow-create: %: %.o $(TAP-OBJS-y) $(BLK-OBJS-y)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS) $(AIOLIBS) $(LDFLAGS_img)

install: all
	$(INSTALL_DIR) -p $(DESTDIR)$(INST_DIR)
	$(INSTALL_PROG) $(IBIN) $(LOCK_UTIL) $(QCOW_UTIL) $(DESTDIR)$(INST_DIR)

clean:
	rm -rf *.o *~ xen TAGS $(IBIN) $(LIB) $(LOCK_UTIL) $(QCOW_UTIL)

.PHONY: clean install
