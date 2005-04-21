XEN_ROOT= ../../../
include $(XEN_ROOT)/tools/Rules.mk
 
TOPDIR= ..
CXXFLAGS=-I. -I../include -I..

ARCH=$(shell uname -i)
ifeq ($(ARCH), i386)
CXXFLAGS+=-D_FILE_OFFSET_BITS=64
endif

OBJS=$(patsubst %.cc,%.o,$(wildcard *.cc))
BXLIBS = ../gui/libgui.a ../memory/libmemory.a  
LDLIBS= $(BXLIBS) $(X11_LDPATH) -lX11 -lXpm -lstdc++ -L../../../tools/libxc -L../../../tools/libxutil -lxc -lxutil -lpthread -lncurses 

all: device-model

device-model: $(OBJS) $(BXLIBS)
	$(CC) $(LDFLAGS) $(OBJS) $(LOADLIBES) $(LDLIBS) -o $@

include $(TOPDIR)/mk/helix.mk

install:: all
	install device-model $(DESTDIR)/usr/sbin
