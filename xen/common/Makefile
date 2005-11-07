
include $(BASEDIR)/Rules.mk

ifeq ($(TARGET_ARCH),ia64)
OBJS := $(subst grant_table.o,,$(OBJS))
endif

ifneq ($(perfc),y)
OBJS := $(subst perfc.o,,$(OBJS))
endif

default: common.o
common.o: $(OBJS)
	$(LD) $(LDFLAGS) -r -o common.o $(OBJS)

clean:
	rm -f *.o *~ core

# Object file contains changeset and compiler information.
kernel.o: $(BASEDIR)/include/xen/compile.h
