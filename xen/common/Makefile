
include $(BASEDIR)/Rules.mk

ifeq ($(TARGET_ARCH),ia64) 
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

ifneq ($(broken_schedulers),y)
OBJS := $(subst sched_atropos.o,,$(OBJS))
OBJS := $(subst sched_fair_bvt.o,,$(OBJS))
OBJS := $(subst sched_rrobin.o,,$(OBJS))
else
CFLAGS += -DBROKEN_SCHEDULERS
endif

default: $(OBJS)
	$(LD) $(LDFLAGS) -r -o common.o $(OBJS)

clean:
	rm -f *.o *~ core
