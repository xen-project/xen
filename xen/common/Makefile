
include $(BASEDIR)/Rules.mk

default: $(OBJS)
	$(LD) $(LDARCHFLAGS) -r -o common.o $(OBJS)

clean:
	rm -f *.o *~ core
