
include $(BASEDIR)/Rules.mk

ifeq ($(TARGET_ARCH),ia64) 
OBJS := $(subst dom_mem_ops.o,,$(OBJS))
OBJS := $(subst grant_table.o,,$(OBJS))
endif

ifneq ($(perfc),y)
OBJS := $(subst perfc.o,,$(OBJS))
endif

ifneq ($(trace),y)
OBJS := $(subst trace.o,,$(OBJS))
endif

default: common.o
common.o: $(OBJS)
	$(LD) $(LDFLAGS) -r -o common.o $(OBJS)

clean:
	rm -f *.o *~ core
