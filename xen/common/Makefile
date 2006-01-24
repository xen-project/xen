
include $(BASEDIR)/Rules.mk

ifneq ($(perfc),y)
OBJS := $(subst perfc.o,,$(OBJS))
endif
ifneq ($(crash_debug),y)
OBJS := $(patsubst gdbstub.o,,$(OBJS))
endif

default: common.o
common.o: $(OBJS)
	$(LD) $(LDFLAGS) -r -o common.o $(OBJS)

clean:
	rm -f *.o *~ core

# Object file contains changeset and compiler information.
kernel.o: $(BASEDIR)/include/xen/compile.h
