
include $(BASEDIR)/Rules.mk

default: $(OBJS)
	$(MAKE) -C tulip
	$(LD) -r -o driver.o tulip/tulip.o $(OBJS)

clean:
	$(MAKE) -C tulip clean
	rm -f *.o *~ core
