CC         = gcc
CFLAGS     = -Wall -O3 
EXTRA_INC  = -I../../xen/include/hypervisor-ifs
EXTRA_INC += -I../../xenolinux-sparse/include -I../xc/lib

HDRS     = $(wildcard *.h)
SRCS     = $(wildcard *.c)
OBJS     = $(patsubst %.c,%.o,$(SRCS))

TARGETS  = xen_cpuperf

INSTALL  = $(TARGETS) xen-mkdevnodes xen_nat_enable xen-clone 

all: $(TARGETS)
	$(MAKE) -C miniterm	

install: all
	mkdir -p $(prefix)/usr/bin
	cp $(INSTALL) $(prefix)/usr/bin
	for i in $(INSTALL); do chmod 755 $(prefix)/usr/bin/$i ; done
	$(MAKE) -C miniterm install

dist: all
	mkdir -p ../../../install/bin
	cp $(INSTALL) ../../../install/bin
	for i in $(INSTALL); do chmod 755 ../../../install/bin/$i ; done
	$(MAKE) -C miniterm dist

clean:
	$(RM) *.o $(TARGETS)
	$(MAKE) -C miniterm clean	

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) $(EXTRA_INC) -o $@ $<

