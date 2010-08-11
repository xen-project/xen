XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

INCLUDES += -I.. -I../lib

IBIN         = fs-backend 

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -fno-strict-aliasing
CFLAGS   += $(CFLAGS_libxenctrl)
CFLAGS   += $(CFLAGS_libxenstore)
CFLAGS   += $(INCLUDES) -I.
CFLAGS   += -D_GNU_SOURCE

LIBS      := -L. -L.. -L../lib
LIBS      += $(LDLIBS_libxenctrl)
LIBS      += $(LDLIBS_libxenstore)
LIBS      += -lrt -lpthread

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
