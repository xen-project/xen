
include $(BASEDIR)/Rules.mk

ifeq ($(nperfc),y)
OBJS := $(subst perfc.o,,$(OBJS))
endif

default: $(OBJS)
	$(LD) $(LDARCHFLAGS) -r -o common.o $(OBJS)

clean:
	rm -f *.o *~ core
