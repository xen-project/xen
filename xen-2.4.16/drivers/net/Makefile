
include $(BASEDIR)/Rules.mk

default: $(OBJS)
	$(MAKE) -C ne
	$(MAKE) -C tulip
	$(MAKE) -C e1000
	$(LD) -r -o driver.o $(OBJS) tulip/tulip.o e1000/e1000.o ne/ne_drv.o

clean:
	$(MAKE) -C ne clean
	$(MAKE) -C tulip clean
	$(MAKE) -C e1000 clean
	rm -f *.o *~ core

.PHONY: default clean
