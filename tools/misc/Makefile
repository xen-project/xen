INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

XEN_ROOT=../..
include $(XEN_ROOT)/tools/Make.defs

CC         = gcc
CFLAGS     = -Wall -Werror -O3 

INCLUDES += -I $(XEN_XC)
INCLUDES += -I $(XEN_LIBXC)
CFLAGS   += $(INCLUDES)

HDRS     = $(wildcard *.h)

TARGETS  = xenperf

INSTALL_BIN  = $(TARGETS) xencons
INSTALL_SBIN = netfix xm xend xensv xenperf

all: $(TARGETS)
	$(MAKE) -C miniterm

install: all
	$(INSTALL_DIR) $(prefix)/usr/bin
	$(INSTALL_DIR) $(prefix)/usr/sbin
	$(INSTALL_PROG) $(INSTALL_BIN) $(prefix)/usr/bin
	$(INSTALL_PROG) $(INSTALL_SBIN) $(prefix)/usr/sbin
	$(MAKE) -C miniterm install

clean:
	$(RM) *.o $(TARGETS) *~
	$(MAKE) -C miniterm clean

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $< -L$(XEN_LIBXC) -lxc -L$(XEN_LIBXUTIL) -lxutil
