
CC       = gcc
CFLAGS  = -Wall -g -O3
CFILES	= $(wildcard *.c)

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

INSTALL_BINS := nsplitd

all: nsplitd

nsplitd: $(OBJS)
	$(CC) $(CFLAGS) -o nsplitd $(OBJS)

install: all

dist: all

clean:
	$(RM) *.o $(INSTALL_BINS)


%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -c -o $@ $<
