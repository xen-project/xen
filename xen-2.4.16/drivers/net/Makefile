
include $(BASEDIR)/Rules.mk

default: $(OBJS)
	$(MAKE) -C tulip
	$(MAKE) -C e1000
	$(LD) -r -o driver.o $(OBJS) tulip/tulip.o e1000/e1000.o

clean:
	$(MAKE) -C tulip clean
	$(MAKE) -C e1000 clean
	rm -f *.o *~ core
