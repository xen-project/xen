
include $(BASEDIR)/Rules.mk

default: $(OBJS)
	$(MAKE) -C tulip
	$(MAKE) -C e100
	$(MAKE) -C e1000
	$(LD) -r -o driver.o e1000/e1000.o $(OBJS) e100/e100.o tulip/tulip.o

clean:
	$(MAKE) -C tulip clean
	$(MAKE) -C e100 clean
	$(MAKE) -C e1000 clean
	rm -f *.o *~ core

.PHONY: default clean
