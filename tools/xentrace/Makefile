INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755
INSTALL_DATA	= $(INSTALL) -m0644

XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Wall -Werror -O3

CFLAGS  += -I $(XEN_XC)
CFLAGS  += -I $(XEN_LIBXC)

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

BIN      = xentrace tbctl setsize
SCRIPTS  = xentrace_format
MAN1     = $(wildcard *.1)
MAN8     = $(wildcard *.8)

all: build
build: $(BIN)

install: build
	[ -d $(DESTDIR)/usr/bin ] || $(INSTALL_DIR) $(DESTDIR)/usr/bin
	[ -d $(DESTDIR)/usr/share/man/man1 ] || \
		$(INSTALL_DIR) $(DESTDIR)/usr/share/man/man1
	[ -d $(DESTDIR)/usr/share/man/man8 ] || \
		$(INSTALL_DIR) $(DESTDIR)/usr/share/man/man8
	$(INSTALL_PROG) $(BIN) $(SCRIPTS) $(DESTDIR)/usr/bin
	$(INSTALL_DATA) $(MAN1) $(DESTDIR)/usr/share/man/man1
	$(INSTALL_DATA) $(MAN8) $(DESTDIR)/usr/share/man/man8

clean:
	$(RM) *.a *.so *.o *.rpm $(BIN)

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $< -L$(XEN_LIBXC) -lxenctrl
