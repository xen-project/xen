XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

INCLUDES += -I.. -I../lib

IBIN         = fs-backend 

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -fno-strict-aliasing
CFLAGS   += -I $(XEN_LIBXC)
CFLAGS   += $(INCLUDES) -I. -I../xenstore 
CFLAGS   += -D_GNU_SOURCE

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS      = .*.d

LIBS      := -L. -L.. -L../lib
LIBS      += -L$(XEN_LIBXC)
LIBS      += -lxenctrl -lpthread -lrt 
LIBS      += -L$(XEN_XENSTORE) -lxenstore

OBJS	  := fs-xenbus.o fs-ops.o

all: $(IBIN)

fs-backend: $(OBJS) fs-backend.c
	$(CC) $(CFLAGS) -o fs-backend $(OBJS) $(LIBS) fs-backend.c

install: all
	$(INSTALL_PROG) $(IBIN) $(DESTDIR)$(SBINDIR)

clean:
	rm -rf *.o *~ $(DEPS) xen $(IBIN) $(LIB)

.PHONY: clean install

-include $(DEPS)
