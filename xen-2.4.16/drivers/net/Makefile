
include $(BASEDIR)/Rules.mk

default: $(OBJS)
	$(MAKE) -C ne
	$(MAKE) -C tulip
	$(LD) -r -o driver.o $(OBJS) tulip/tulip.o ne/ne_drv.o

clean:
	$(MAKE) -C ne clean
	$(MAKE) -C tulip clean
	rm -f *.o *~ core

.PHONY: default clean
