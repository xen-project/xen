
include $(BASEDIR)/Rules.mk

default: $(OBJS)
	$(MAKE) -C tulip
	$(LD) -r -o driver.o $(OBJS) tulip/tulip.o 

clean:
	$(MAKE) -C tulip clean
	rm -f *.o *~ core
