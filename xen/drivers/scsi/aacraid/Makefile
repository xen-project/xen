
include $(BASEDIR)/Rules.mk

CFLAGS	+= -I$(BASEDIR)/drivers/scsi

default: $(OBJS)
	$(LD) -r -o aacraid.o $(OBJS)

clean:
	rm -f *.o *~ core



