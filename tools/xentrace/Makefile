
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
	mkdir -p /usr/bin
	cp $(BIN) /usr/bin
	for i in $(BIN); do chmod 755 /usr/bin/$$i; done
	for i in $(MAN1); do cp $$i /usr/man/man1/$$i; done
	for i in $(MAN8); do cp $$i /usr/man/man8/$$i; done

dist: all
	mkdir -p ../../../install/bin
	cp $(BIN) ../../../install/bin
	chmod 755 ../../../install/bin/$(BIN)
	cp $(SCRIPTS) ../../../install/bin
	for i in $(SCRIPTS); do chmod 755 ../../../install/bin/$i; done

clean:
	$(RM) *.a *.so *.o *.rpm $(BIN)

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $< -L../xc/lib -lxc
