
include $(BASEDIR)/Rules.mk

default: $(OBJS)
	$(MAKE) -C ne
	$(MAKE) -C tulip
	$(MAKE) -C e1000
	$(LD) -r -o driver.o e1000/e1000.o $(OBJS) tulip/tulip.o ne/ne_drv.o

clean:
	$(MAKE) -C ne clean
	$(MAKE) -C tulip clean
	rm -f *.o *~ core

.PHONY: default clean
