XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

IBIN         = blktapctrl tapdisk
QCOW_UTIL    = img2qcow qcow2raw qcow-create
MEMSHR_DIR   = ../../memshr

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -I../lib
CFLAGS   += $(CFLAGS_libxenctrl)
CFLAGS   += $(CFLAGS_libxenstore)
CFLAGS   += -I $(MEMSHR_DIR)
CFLAGS   += -D_GNU_SOURCE

ifeq ($CONFIG_GCRYPT,y)
CFLAGS += -DUSE_GCRYPT
CRYPT_LIB := -lgcrypt
else
CRYPT_LIB := -lcrypto
$(warning === libgcrypt not installed: falling back to libcrypto ===)
endif

MEMSHRLIBS :=
ifeq ($(CONFIG_Linux), y)
CFLAGS += -DMEMSHR
MEMSHRLIBS += $(MEMSHR_DIR)/libmemshr.a
endif

ifneq ($(CONFIG_SYSTEM_LIBAIO),y)
LIBAIO_DIR   = ../../libaio/src
CFLAGS      += -I $(LIBAIO_DIR)
AIOLIBS     := $(LIBAIO_DIR)/libaio.a
else
AIOLIBS     := -laio
endif

LDLIBS_blktapctrl := $(MEMSHRLIBS) $(LDLIBS_libxenctrl) $(LDLIBS_libxenstore) -L../lib -lblktap -lrt -lm -lpthread
LDLIBS_img := $(AIOLIBS) $(CRYPT_LIB) -lpthread -lz

BLK-OBJS-y  := block-aio.o
BLK-OBJS-y  += block-sync.o
BLK-OBJS-y  += block-vmdk.o
BLK-OBJS-y  += block-ram.o
BLK-OBJS-y  += block-qcow.o
BLK-OBJS-y  += block-qcow2.o
BLK-OBJS-y  += aes.o
BLK-OBJS-y  += tapaio.o
BLK-OBJS-$(CONFIG_Linux) += blk_linux.o

BLKTAB-OBJS-y := blktapctrl.o
BLKTAB-OBJS-$(CONFIG_Linux) += blktapctrl_linux.o

all: $(IBIN) qcow-util

blktapctrl: $(BLKTAB-OBJS-y)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS_blktapctrl)

tapdisk: tapdisk.o $(BLK-OBJS-y)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS_img)

.PHONY: qcow-util
qcow-util: img2qcow qcow2raw qcow-create

img2qcow qcow2raw qcow-create: %: %.o $(BLK-OBJS-y)
	$(CC) $(LDFLAGS) -o $* $^ $(LDLIBS_img)

install: all
	$(INSTALL_PROG) $(IBIN) $(QCOW_UTIL) $(VHD_UTIL) $(DESTDIR)$(SBINDIR)

clean:
	rm -rf *.o *~ $(DEPS) xen TAGS $(IBIN) $(LIB) $(QCOW_UTIL) $(VHD_UTIL)

.PHONY: clean install

-include $(DEPS)
