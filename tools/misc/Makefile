INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS   += -Wall -Werror -O3 

INCLUDES += -I $(XEN_XC)
INCLUDES += -I $(XEN_LIBXC)
CFLAGS   += $(INCLUDES)

HDRS     = $(wildcard *.h)

TARGETS  = xenperf xc_shadow

INSTALL_BIN  = $(TARGETS) xencons
INSTALL_SBIN = netfix xm xend xensv xenperf

all: build
build: $(TARGETS)
	$(MAKE) -C miniterm
	$(MAKE) -C cpuperf

install: build
	[ -d $(DESTDIR)/usr/bin ] || $(INSTALL_DIR) $(DESTDIR)/usr/bin
	[ -d $(DESTDIR)/usr/sbin ] || $(INSTALL_DIR) $(DESTDIR)/usr/sbin
	$(INSTALL_PROG) $(INSTALL_BIN) $(DESTDIR)/usr/bin
	$(INSTALL_PROG) $(INSTALL_SBIN) $(DESTDIR)/usr/sbin
	$(MAKE) -C cpuperf install
#       No sense in installing miniterm on the Xen box.
#	$(MAKE) -C miniterm install

clean:
	$(RM) *.o $(TARGETS) *~
	$(MAKE) -C miniterm clean
	$(MAKE) -C cpuperf clean

%.o: %.c $(HDRS) Makefile
	$(CC) -c $(CFLAGS) -o $@ $<

$(TARGETS): %: %.o Makefile
	$(CC) $(CFLAGS) -o $@ $< -L$(XEN_LIBXC) -lxc -L$(XEN_LIBXUTIL) -lxutil
