
XEN_ROOT=../..
include $(XEN_ROOT)/tools/Make.defs

CC         = gcc
CFLAGS     = -Wall -O3 

INCLUDES += -I $(XEN_LINUX_INCLUDE)
INCLUDES += -I $(XEN_XC)
INCLUDES += -I $(XEN_LIBXC)
INCLUDES += -I $(XEN_LIBXUTIL)

CFLAGS += $(INCLUDES)

HDRS     = $(wildcard *.h)
SRCS     = $(wildcard *.c)
OBJS     = $(patsubst %.c,%.o,$(SRCS))

TARGETS  = 

INSTALL_BIN  = $(TARGETS) xencons
INSTALL_SBIN = netfix xm xend xensv

all: $(TARGETS)
	$(MAKE) -C miniterm

install: all
	mkdir -p $(prefix)/usr/bin
	mkdir -p $(prefix)/usr/sbin
	install -m0755 $(INSTALL_BIN) $(prefix)/usr/bin
	install -m0755 $(INSTALL_SBIN) $(prefix)/usr/sbin
	$(MAKE) -C miniterm install

clean:
	$(RM) *.o $(TARGETS) *~
	$(MAKE) -C miniterm clean	

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $<
