XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -I$(XEN_LIBXC) -I$(XEN_XENSTORE)
CFLAGS  += -I$(XEN_ROOT)/linux-2.6-xen-sparse/include -I$(XEN_ROOT)/tools/ioemu
LDFLAGS += -L$(XEN_LIBXC) -L$(XEN_XENSTORE)

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) vncfb sdlfb

install: all
	$(INSTALL_DIR) $(DESTDIR)/usr/$(LIBDIR)/xen/bin
	$(INSTALL_PROG) vncfb $(DESTDIR)/usr/$(LIBDIR)/xen/bin/xen-vncfb
	$(INSTALL_PROG) sdlfb $(DESTDIR)/usr/$(LIBDIR)/xen/bin/xen-sdlfb

sdlfb: sdlfb.o xenfb.o

sdlfb.o: CFLAGS += $(shell sdl-config --cflags)
sdlfb: LDLIBS += $(shell sdl-config --libs) -lxenctrl -lxenstore

clean:
	$(RM) *.o *~ vncfb sdlfb

vncfb: vncfb.o xenfb.o
vncfb.o: CFLAGS += $(shell libvncserver-config --cflags)
vncfb: LDLIBS += $(shell libvncserver-config --libs) -lxenctrl -lxenstore

sdlfb.o xenfb.o vncfb.o: xenfb.h
