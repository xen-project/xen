XEN_ROOT=$(CURDIR)/../../..
BLKTAP_ROOT= ..
include $(XEN_ROOT)/tools/Rules.mk

LIBVHDDIR  = $(BLKTAP_ROOT)/vhd/lib

IBIN       = tapdisk2 td-util tapdisk-client tapdisk-stream tapdisk-diff
QCOW_UTIL  = img2qcow qcow-create qcow2raw
LOCK_UTIL  = lock-util
INST_DIR   = $(sbindir)

CFLAGS    += -Werror
CFLAGS    += -Wno-unused
CFLAGS    += -fno-strict-aliasing
CFLAGS    += -I$(BLKTAP_ROOT)/include -I$(BLKTAP_ROOT)/drivers
CFLAGS    += $(CFLAGS_libxenctrl)
CFLAGS    += -D_GNU_SOURCE
CFLAGS    += -DUSE_NFS_LOCKS
# drivers/block-log.c incorrectly uses libxc internals
CFLAGS    += -I$(XEN_ROOT)/tools/libxc

ifeq ($(CONFIG_X86_64),y)
CFLAGS            += -fPIC
endif

VHDLIBS    := -L$(LIBVHDDIR) -lvhd

REMUS-OBJS  := block-remus.o
REMUS-OBJS  += hashtable.o
REMUS-OBJS  += hashtable_itr.o
REMUS-OBJS  += hashtable_utility.o

tapdisk2 tapdisk-stream tapdisk-diff $(QCOW_UTIL): AIOLIBS := -laio

MEMSHRLIBS :=
ifeq ($(CONFIG_Linux), __fixme__)
MEMSHR_DIR = $(XEN_ROOT)/tools/memshr
CFLAGS += -DMEMSHR
CFLAGS += -I $(MEMSHR_DIR)
MEMSHRLIBS += -L$(XEN_ROOT)/tools/libxc -lxenctrl $(MEMSHR_DIR)/libmemshr.a
endif

ifeq ($(VHD_STATIC),y)
td-util: CFLAGS += -static
endif

PORTABLE-OBJS-y :=
PORTABLE-OBJS-$(CONFIG_Linux)  += blk_linux.o
PORTABLE-OBJS-$(CONFIG_NetBSD) += blk_netbsd.o

TAP-OBJS-y  := scheduler.o
TAP-OBJS-y  += tapdisk-vbd.o
TAP-OBJS-y  += tapdisk-control.o
TAP-OBJS-y  += tapdisk-image.o
TAP-OBJS-y  += tapdisk-driver.o
TAP-OBJS-y  += tapdisk-disktype.o
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
BLK-OBJS-y  += md5.o
BLK-OBJS-y  += $(PORTABLE-OBJS-y)
BLK-OBJS-y  += $(REMUS-OBJS)

all: $(IBIN) lock-util qcow-util


tapdisk2: $(TAP-OBJS-y) $(BLK-OBJS-y) $(MISC-OBJS-y) tapdisk2.o
	$(CC) -o $@ $^ $(LDFLAGS) -lrt -lz $(VHDLIBS) $(AIOLIBS) $(MEMSHRLIBS) -lm  $(APPEND_LDFLAGS)

tapdisk-client: tapdisk-client.o
	$(CC) -o $@ $^ $(LDFLAGS) -lrt $(APPEND_LDFLAGS)

tapdisk-stream tapdisk-diff: %: %.o $(TAP-OBJS-y) $(BLK-OBJS-y)
	$(CC) -o $@ $^ $(LDFLAGS) -lrt -lz $(VHDLIBS) $(AIOLIBS) $(MEMSHRLIBS) -lm $(APPEND_LDFLAGS)

td-util: td.o tapdisk-utils.o tapdisk-log.o $(PORTABLE-OBJS-y)
	$(CC) -o $@ $^ $(LDFLAGS) $(VHDLIBS) $(APPEND_LDFLAGS)

lock-util: lock.c
	$(CC) $(CFLAGS) -DUTIL -o lock-util lock.c $(LDFLAGS) $(APPEND_LDFLAGS)

.PHONY: qcow-util
qcow-util: img2qcow qcow2raw qcow-create

img2qcow qcow2raw qcow-create: %: %.o $(TAP-OBJS-y) $(BLK-OBJS-y)
	$(CC) -o $@ $^ $(LDFLAGS) -lrt -lz $(VHDLIBS) $(AIOLIBS) $(MEMSHRLIBS) -lm $(APPEND_LDFLAGS)

install: all
	$(INSTALL_DIR) -p $(DESTDIR)$(INST_DIR)
	$(INSTALL_PROG) $(IBIN) $(LOCK_UTIL) $(QCOW_UTIL) $(DESTDIR)$(INST_DIR)

uninstall:
	rm -f $(addprefix $(DESTDIR)$(INST_DIR)/, $(IBIN) $(LOCK_UTIL) $(QCOW_UTIL))

clean:
	rm -rf .*.d *.o *~ xen TAGS $(IBIN) $(LIB) $(LOCK_UTIL) $(QCOW_UTIL)

distclean: clean

.PHONY: clean install distclean uninstall
