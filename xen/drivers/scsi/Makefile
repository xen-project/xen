
include $(BASEDIR)/Rules.mk

default: $(OBJS)
	$(MAKE) -C aacraid
	$(MAKE) -C aic7xxx
	$(LD) -r -o driver.o $(OBJS) aacraid/aacraid.o aic7xxx/aic7xxx.o
#	$(LD) -r -o driver.o $(OBJS) 

clean:
	$(MAKE) -C aacraid clean
	$(MAKE) -C aic7xxx clean
	rm -f *.o *~ core
