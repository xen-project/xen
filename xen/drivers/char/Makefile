
include $(BASEDIR)/Rules.mk

default: driver.o
driver.o: $(OBJS)
	$(LD) $(LDFLAGS) -r -o driver.o $(OBJS)

console.o: ../../include/xen/banner.h

clean:
	rm -f *.o *~ core
