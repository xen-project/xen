
CC        = gcc
CFLAGS    = -Wall -O3 
EXTRA_INC = -I../../xen/include -I../../xenolinux-sparse/include -I../xc/lib

HDRS     = $(wildcard *.h)
SRCS     = $(wildcard *.c)
OBJS     = $(patsubst %.c,%.o,$(SRCS))

INSTALL  = $(wildcard *.py)
ETC	 = defaults democd

all: 

install: all
	mkdir -p /usr/bin
	cp -a $(INSTALL) /usr/bin
	#chmod 755 $(INSTALL)
	mkdir -p /etc/xc
	for i in $(ETC) ; do [ ! -e /etc/xc/$$i ] && echo Install $$i && cp $$i /etc/xc/ ; done || true 

dist: all
	mkdir -p ../../../install/bin
	mkdir -p ../../../install/etc
	cp -a $(INSTALL) ../../../install/bin
	cp -a $(ETC) ../../../install/etc
	#chmod 755 $(INSTALL)

clean:


%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) $(EXTRA_INC) -o $@ $<

