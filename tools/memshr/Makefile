XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

LIBMEMSHR-BUILD := libmemshr.a

CFLAGS          += -Werror
CFLAGS          += -Wno-unused
CFLAGS          += -I../include
CFLAGS          += $(CFLAGS_libxenctrl)
CFLAGS          += -D_GNU_SOURCE
CFLAGS          += -fPIC
CFLAGS          += -g

# Get gcc to generate the dependencies for us.
CFLAGS          += -Wp,-MD,.$(@F).d
DEPS             = .*.d

LIB-SRCS        := interface.c
LIB-SRCS        += shm.c
LIB-SRCS        += bidir-hash.c

LIB-OBJS        := interface.o
LIB-OBJS        += shm.o
LIB-OBJS        += bidir-hash-fgprtshr.o
LIB-OBJS        += bidir-hash-blockshr.o

all: build

build: $(LIBMEMSHR-BUILD)

bidir-hash-fgprtshr.o: bidir-hash.c
	$(CC) $(CFLAGS) -DFINGERPRINT_MAP -c -o $*.o bidir-hash.c 

bidir-hash-blockshr.o: bidir-hash.c
	$(CC) $(CFLAGS) -DBLOCK_MAP -c -o $*.o bidir-hash.c 

libmemshr.a: $(LIB-OBJS)
	$(AR) rc $@ $^

install: all

clean:
	rm -rf *.a *.o *~ $(DEPS)

.PHONY: all build clean install

-include $(DEPS)
