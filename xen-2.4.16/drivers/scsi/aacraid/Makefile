
include $(BASEDIR)/Rules.mk

CFLAGS	+= -I$(BASEDIR)/drivers/scsi


# -y		:= linit.o aachba.o commctrl.o comminit.o commsup.o \
# 		   dpcsup.o rx.o sa.o

default: $(OBJS)
	$(LD) -r -o aacraid.o $(OBJS)

clean:
	rm -f *.o *~ core



