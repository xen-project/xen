
include $(BASEDIR)/Rules.mk

# naive OBJS rule gets link order wrong
FUSIONOBJS := mptbase.o mptscsih.o

default: $(OBJS)
	$(LD) -r -o driver.o $(FUSIONOBJS)

clean:
	rm -f *.o *~ core
