
include $(BASEDIR)/Rules.mk

ifeq ($(TARGET_ARCH),ia64) 
OBJS := $(subst dom_mem_ops.o,,$(OBJS))
OBJS := $(subst grant_table.o,,$(OBJS))
OBJS := $(subst page_alloc.o,,$(OBJS))
OBJS := $(subst slab.o,,$(OBJS))
endif

ifneq ($(debugger),y)
OBJS := $(subst debug.o,,$(OBJS))
OBJS := $(subst debug-linux.o,,$(OBJS))
endif

ifneq ($(perfc),y)
OBJS := $(subst perfc.o,,$(OBJS))
endif

ifneq ($(trace),y)
OBJS := $(subst trace.o,,$(OBJS))
endif

OBJS := $(subst sched_atropos.o,,$(OBJS))
OBJS := $(subst sched_rrobin.o,,$(OBJS))

default: common.o
common.o: $(OBJS)
	$(LD) $(LDFLAGS) -r -o common.o $(OBJS)

clean:
	rm -f *.o *~ core
