
CC       = gcc
CFLAGS   = -Wall -O3 
CFLAGS  += -I../xc/lib

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

BIN      = xend

all: $(BIN)

install: all
	mkdir -p $(prefix)/usr/sbin
	cp $(BIN) $(prefix)/usr/sbin
	chmod 755 $(prefix)/usr/sbin/$(BIN)

dist: all
	mkdir -p ../../../install/sbin
	cp $(BIN) ../../../install/sbin
	chmod 755 ../../../install/sbin/$(BIN)

clean:
	$(RM) *.a *.so *.o *.rpm $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $@ $^ -L../xc/lib -lxc

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -c -o $@ $<
