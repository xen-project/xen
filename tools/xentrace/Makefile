
CC       = gcc
CFLAGS   = -Wall -O3 
CFLAGS  += -I../../xen/include/hypervisor-ifs
CFLAGS  += -I../../xenolinux-sparse/include

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

BIN      = xentrace
SCRIPTS  = $(wildcard *.py)

all: $(BIN)

install: all
	mkdir -p /usr/bin
	cp $(BIN) /usr/bin
	cp $(SCRIPTS) /usr/bin
	chmod 755 /usr/bin/$(BIN)
	for i in $(SCRIPTS); do chmod 755 /usr/bin/$$i; done

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
