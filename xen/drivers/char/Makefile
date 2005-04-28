
include $(BASEDIR)/Rules.mk

default: driver.o
driver.o: $(OBJS)
	$(LD) $(LDFLAGS) -r -o driver.o $(OBJS)

clean:
	rm -f *.o *~ core
