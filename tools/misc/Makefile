
CC       = gcc
CFLAGS   = -Wall -O3 
CFLAGS  += -I../../xen/include -I../../xenolinux-sparse/include -I../internal

HDRS     = $(wildcard *.h)
SRCS     = $(wildcard *.c)
OBJS     = $(patsubst %.c,%.o,$(SRCS))

TARGETS  = xen_read_console xen_cpuperf

INSTALL  = $(TARGETS) xen-mkdevnodes xen-clone

all: $(TARGETS)
	$(MAKE) -C miniterm	

install: all
	mkdir -p ../../../install/bin
	cp -a $(INSTALL) ../../../install/bin
	chmod 755 ../../../install/bin/xen-mkdevnodes
	chmod 755 ../../../install/bin/xen-clone
	$(MAKE) -C miniterm install

clean:
	$(RM) *.o $(TARGETS)
	$(MAKE) -C miniterm clean	

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $<

