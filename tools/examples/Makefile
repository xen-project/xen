
CC        = gcc
CFLAGS    = -Wall -O3 
EXTRA_INC = -I../../xen/include -I../../xenolinux-sparse/include -I../xc/lib

HDRS     = $(wildcard *.h)
SRCS     = $(wildcard *.c)
OBJS     = $(patsubst %.c,%.o,$(SRCS))

INSTALL  = $(wildcard *.py)
ETC	 = defaults democd netbsd
INITD    = xendomains

all: 

install: all
	mkdir -p $(prefix)/usr/bin
	cp -a $(INSTALL) $(prefix)/usr/bin
	#chmod 755 $(INSTALL)
	mkdir -p $(prefix)/etc/xc
	for i in $(ETC) ; do [ ! -e $(prefix)/etc/xc/$$i ] && echo Install $$i && cp $$i $(prefix)/etc/xc/ ; done || true
	mkdir -p $(prefix)/etc/xc/auto
	for i in $(INITD) ; do [ -e $(prefix)/etc/init.d/ ] && [ ! -e $(prefix)/etc/init.d/$$i ] && cp $$i $(prefix)/etc/init.d/ ; done || true

dist: all
	mkdir -p ../../../install/bin
	mkdir -p ../../../install/etc
	mkdir -p ../../../install/init.d
	install --mode=555 $(INSTALL) ../../../install/bin
	install --mode=444 $(ETC) ../../../install/etc
	#chmod 755 $(INSTALL)
	install --mode=555 $(INITD) ../../../install/init.d

clean:


%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) $(EXTRA_INC) -o $@ $<

