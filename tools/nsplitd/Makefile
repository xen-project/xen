ROOT	= ..

CFILES	= $(wildcard *.c)

INSTALL_BINS := nsplitd

include $(ROOT)/mk/rules.mk

nsplitd: $(OBJS)
	$(CC) $(CFLAGS) -o nsplitd $(OBJS)

