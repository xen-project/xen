TOPDIR= ..
CXXFLAGS=-I. -I../include -I..
OBJS= gui.o keymap.o siminterface.o textconfig.o x.o

all: libgui.a

libgui.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

include $(TOPDIR)/mk/helix.mk
