
CC       = gcc
CFLAGS   = -Wall -O3 -Werror
CFLAGS  += -I../../xen/include/hypervisor-ifs
CFLAGS  += -I../../linux-xen-sparse/include
CFLAGS  += -I../xu/lib
CFLAGS  += -I../lib

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

BIN      = xentrace
SCRIPTS  = xentrace_format
MAN1     = $(wildcard *.1)
MAN8     = $(wildcard *.8)

all: $(BIN)

install: all
	mkdir -p $(prefix)/usr/bin
	mkdir -p $(prefix)/usr/man/man1
	mkdir -p $(prefix)/usr/man/man8
	install -m0755 $(BIN) $(SCRIPTS) $(prefix)/usr/bin
	install -m0644 $(MAN1) $(prefix)/usr/man/man1
	install -m0644 $(MAN8) $(prefix)/usr/man/man8

clean:
	$(RM) *.a *.so *.o *.rpm $(BIN)

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $< -L../xc/lib -lxc
