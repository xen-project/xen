
include $(BASEDIR)/Rules.mk

default: $(OBJS)
	$(MAKE) -C aacraid
	$(LD) -r -o driver.o $(OBJS) aacraid/aacraid.o
#	$(LD) -r -o driver.o $(OBJS) 

clean:
	$(MAKE) -C aacraid clean
	rm -f *.o *~ core
