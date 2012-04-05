XEN_ROOT = $(CURDIR)/../../..
BLKTAP_ROOT := ..
include $(XEN_ROOT)/tools/Rules.mk

ifeq ($(LVM_UTIL_TEST),y)
TEST              := lvm-util
endif

CFLAGS            += -Werror
CFLAGS            += -Wno-unused
CFLAGS            += -I../include
CFLAGS            += -D_GNU_SOURCE

ifeq ($(CONFIG_X86_64),y)
CFLAGS            += -fPIC
endif

LVM-OBJS          := lvm-util.o

all: build

build: $(TEST) $(LVM-OBJS)

install: all

lvm-util: lvm-util.o
	$(CC) -DLVM_UTIL $(LDFLAGS) -o lvm-util lvm-util.c

clean:
	rm -rf *.o *.opic *~ $(DEPS) $(IBIN)

.PHONY: all build clean install lvm-util

-include $(DEPS)
