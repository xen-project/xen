#
# Make Performance counter tool
#
# $Id: Makefile,v 1.1 2003/10/13 16:49:44 jrb44 Exp $
#
# $Log: Makefile,v $
# Revision 1.1  2003/10/13 16:49:44  jrb44
# Initial revision
#
#

INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

# these are for Xen
XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS      += -O3 

HDRS         = $(wildcard *.h)
SRCS         = $(wildcard *.c)
OBJS         = $(patsubst %.c,%.o,$(SRCS))

TARGETS      = cpuperf-xen cpuperf-perfcntr

INSTALL_BIN  = $(TARGETS)


all: $(TARGETS)

clean:
	$(RM) *.o $(TARGETS)

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $<

cpuperf-xen: cpuperf.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -I $(XEN_LIBXC) -L$(XEN_LIBXC) -lxenctrl -DXENO -o $@ $<

cpuperf-perfcntr: cpuperf.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -DPERFCNTR -o $@ $<

install: all
	$(INSTALL_PROG) $(INSTALL_BIN) $(DESTDIR)/usr/bin


# End of $RCSfile: Makefile,v $

