TOPDIR= ..
CXXFLAGS=-I. -I../include -I..
OBJS= memory.o misc_mem.o

all: libmemory.a

libmemory.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

include $(TOPDIR)/mk/helix.mk

install:: all
