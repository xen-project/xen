
include $(BASEDIR)/Rules.mk

default: $(OBJS)
	$(LD) $(LDFLAGS) -r -o driver.o $(OBJS)

clean:
	rm -f *.o *~ core
