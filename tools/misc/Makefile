
CC         = gcc
CFLAGS     = -Wall -O3 
EXTRA_INC  = -I../../xen/include/hypervisor-ifs
EXTRA_INC += -I../../linux-xen-sparse/include -I../xc/lib
EXTRA_INC += -I../xu/lib
EXTRA_INC += -I../lib

HDRS     = $(wildcard *.h)
SRCS     = $(wildcard *.c)
OBJS     = $(patsubst %.c,%.o,$(SRCS))

TARGETS  = xen_cpuperf

INSTALL  = $(TARGETS) xencons

all: $(TARGETS)
	$(MAKE) -C miniterm

install: all
	mkdir -p $(prefix)/usr/bin
	install -m0755 $(INSTALL) $(prefix)/usr/bin
	install -m0755 netfix $(prefix)/usr/sbin
	$(MAKE) -C miniterm install

clean:
	$(RM) *.o $(TARGETS) *~
	$(MAKE) -C miniterm clean	

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) $(EXTRA_INC) -o $@ $<
