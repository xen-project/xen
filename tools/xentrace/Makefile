INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755
INSTALL_DATA	= $(INSTALL) -m0644

XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CC       = gcc
CFLAGS  += -Wall -Werror -O3

CFLAGS  += -I $(XEN_XC)
CFLAGS  += -I $(XEN_LIBXC)
CFLAGS  += -I $(XEN_LIBXUTIL)

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

BIN      = xentrace
SCRIPTS  = xentrace_format
MAN1     = $(wildcard *.1)
MAN8     = $(wildcard *.8)

all: $(BIN)

install: all
	$(INSTALL_DIR) $(DESTDIR)/usr/bin
	$(INSTALL_DIR) $(DESTDIR)/usr/man/man1
	$(INSTALL_DIR) $(DESTDIR)/usr/man/man8
	$(INSTALL_PROG) $(BIN) $(SCRIPTS) $(DESTDIR)/usr/bin
	$(INSTALL_DATA) $(MAN1) $(DESTDIR)/usr/man/man1
	$(INSTALL_DATA) $(MAN8) $(DESTDIR)/usr/man/man8

clean:
	$(RM) *.a *.so *.o *.rpm $(BIN)

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $< -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -lxc -lxutil
