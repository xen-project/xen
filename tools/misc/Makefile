
CC        = gcc
CFLAGS    = -Wall -O3 
EXTRA_INC = -I../../xen/include -I../../xenolinux-sparse/include -I../xc/lib

HDRS     = $(wildcard *.h)
SRCS     = $(wildcard *.c)
OBJS     = $(patsubst %.c,%.o,$(SRCS))

TARGETS  = xen_read_console xen_refresh_dev xen_cpuperf

INSTALL  = $(TARGETS) xen-mkdevnodes xen_nat_enable xen-clone 
INSTALL += xi_createlinuxdom.py xi_destroydom.py xi_listdoms.py
INSTALL += xi_stopdom.py

all: $(TARGETS)
	$(MAKE) -C miniterm	

install: all
	mkdir -p ../../../install/bin
	cp -a $(INSTALL) ../../../install/bin
	chmod 755 ../../../install/bin/xen-mkdevnodes
	chmod 755 ../../../install/bin/xen_nat_enable
	chmod 755 ../../../install/bin/xen-clone
	chmod 755 ../../../install/bin/xi_createlinuxdom.py
	chmod 755 ../../../install/bin/xi_destroydom.py
	chmod 755 ../../../install/bin/xi_listdoms.py
	chmod 755 ../../../install/bin/xi_stopdom.py
	$(MAKE) -C miniterm install

clean:
	$(RM) *.o $(TARGETS)
	$(MAKE) -C miniterm clean	

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) $(EXTRA_INC) -o $@ $<

