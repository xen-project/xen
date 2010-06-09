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

OBJS = $(CTL_OBJS)
LIBS = libblktapctl.a

all: build

build: $(IBIN)

tap-ctl: tap-ctl.o libblktapctl.a
	$(CC) $(CFLAGS) -o $@ $^

libblktapctl.a: $(CTL_OBJS)
	ar r $@ $^

install: all
	$(INSTALL_DIR) -p $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) $(IBIN) $(DESTDIR)$(SBINDIR)

clean:
	rm -f $(OBJS) $(DEPS) $(IBIN) $(LIBS)
	rm -f *~

.PHONY: all build clean install

-include $(DEPS)
