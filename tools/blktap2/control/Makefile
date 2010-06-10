XEN_ROOT := ../../../
include $(XEN_ROOT)/tools/Rules.mk

IBIN               = tap-ctl

CFLAGS            += -Werror
CFLAGS            += -Wno-unused
CFLAGS            += -I../include -I../drivers
CFLAGS            += -I$(XEN_INCLUDE) -I$(XEN_LIBXC)
CFLAGS            += -D_GNU_SOURCE
CFLAGS            += -DTAPCTL

# Get gcc to generate the dependencies for us.
CFLAGS            += -Wp,-MD,.$(@F).d
DEPS               = .*.d

CTL_OBJS  := tap-ctl-ipc.o
CTL_OBJS  += tap-ctl-list.o
CTL_OBJS  += tap-ctl-allocate.o
CTL_OBJS  += tap-ctl-free.o
CTL_OBJS  += tap-ctl-create.o
CTL_OBJS  += tap-ctl-destroy.o
CTL_OBJS  += tap-ctl-spawn.o
CTL_OBJS  += tap-ctl-attach.o
CTL_OBJS  += tap-ctl-detach.o
CTL_OBJS  += tap-ctl-open.o
CTL_OBJS  += tap-ctl-close.o
CTL_OBJS  += tap-ctl-pause.o
CTL_OBJS  += tap-ctl-unpause.o
CTL_OBJS  += tap-ctl-major.o
CTL_OBJS  += tap-ctl-check.o

CTL_PICS  = $(patsubst %.o,%.opic,$(CTL_OBJS))

OBJS = $(CTL_OBJS) tap-ctl.o
PICS = $(CTL_PICS)

LIBS = libblktapctl.a libblktapctl.so
IBIN = tap-ctl

all: build

build: $(IBIN) $(LIBS)

tap-ctl: tap-ctl.o libblktapctl.so
	$(CC) $(CFLAGS) -o $@ $^

libblktapctl.a: $(CTL_OBJS)
	$(AR) r $@ $^

libblktapctl.so: $(CTL_PICS)
	$(CC) $(CFLAGS) -fPIC -shared -rdynamic $^ -o $@

install: $(IBIN) $(LIBS)
	$(INSTALL_DIR) -p $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) $(IBIN) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) $(LIBS) $(DESTDIR)$(LIBDIR)

clean:
	rm -f $(OBJS) $(PICS) $(DEPS) $(IBIN) $(LIBS)
	rm -f *~

.PHONY: all build clean install

-include $(DEPS)
