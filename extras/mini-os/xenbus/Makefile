all: xenstore.h xenbus_comms.o xenbus_xs.o xenbus_probe.o

xenstore.h:
	[ -e xenstored.h ] || ln -sf ../../../tools/xenstore/xenstored.h xenstored.h

clean:
	#Taken care of by main Makefile
	#rm xenstored.h
	#rm *.o
