
CC       = gcc
CFLAGS   = -Wall -O3 
CFLAGS  += -I../../xen/include/hypervisor-ifs
CFLAGS  += -I../../xenolinux-sparse/include

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

BIN      = xentrace xentrace_cpusplit xentrace_format
MAN1     = $(wildcard *.1)
MAN8     = $(wildcard *.8)

all: $(BIN)

install: all
	mkdir -p $(prefix)/usr/bin
	mkdir -p $(prefix)/usr/man/man1
	mkdir -p $(prefix)/usr/man/man8
	install -m0755 $(BIN) $(prefix)/usr/bin
	install -m0644 $(MAN1) $(prefix)/usr/man/man1
	install -m0644 $(MAN8) $(prefix)/usr/man/man8

clean:
	$(RM) *.a *.so *.o *.rpm $(BIN)

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $< -L../xc/lib -lxc
