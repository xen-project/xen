TOPDIR= ..
CXXFLAGS=-I. -I../include -I..
OBJS=$(patsubst %.cc,%.o,$(wildcard *.cc))
BXLIBS = ../gui/libgui.a ../memory/libmemory.a  
LDLIBS= $(BXLIBS) -L/usr/X11R6/lib -lX11 -lXpm -lstdc++ -L ../../../tools/libxc -L ../../../tools/libxutil -lxc -lxutil -lpthread -lncurses

all: device-model

device-model: $(OBJS) $(BXLIBS)
	$(LINK.o) $(OBJS) $(LOADLIBES) $(LDLIBS) -o $@

include $(TOPDIR)/mk/helix.mk

install:: all
	install device-model $(DESTDIR)/usr/sbin
