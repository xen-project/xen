
CC        = gcc
CFLAGS    = -Wall -O3 
EXTRA_INC = -I../../xen/include -I../../xenolinux-sparse/include -I../internal

HDRS     = $(wildcard *.h)
SRCS     = $(wildcard *.c)
OBJS     = $(patsubst %.c,%.o,$(SRCS))

TARGETS  = xen_read_console xen_cpuperf xen_refresh_dev xen_netwatch

INSTALL  = $(TARGETS) xen-mkdevnodes xen_nat_enable xen-clone 

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

xen_netwatch: %: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $<

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) $(EXTRA_INC) -o $@ $<

