
include $(BASEDIR)/Rules.mk

ifeq ($(nperfc),y)
OBJS := $(subst perfc.o,,$(OBJS))
endif

ifeq ($(nodev),y)
OBJS := $(subst network.o,,$(OBJS))
endif

default: $(OBJS)
	$(LD) $(LDARCHFLAGS) -r -o common.o $(OBJS)

clean:
	rm -f *.o *~ core
