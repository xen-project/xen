
include $(BASEDIR)/Rules.mk

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

default: $(OBJS)
	$(LD) $(LDFLAGS) -r -o common.o $(OBJS)

clean:
	rm -f *.o *~ core
