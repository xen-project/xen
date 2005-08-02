# Makefile for consoled
# based on xcs Makefile
# Anthony Liguori 2005

XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CONSOLED_INSTALL_DIR = /usr/sbin
XC_CONSOLE_INSTALL_DIR = /usr/libexec/xen

INSTALL         = install
INSTALL_PROG    = $(INSTALL) -m0755
INSTALL_DIR     = $(INSTALL) -d -m0755

CC       = gcc
CFLAGS   = -Wall -Werror -g3

CFLAGS  += -I $(XEN_XCS)
CFLAGS  += -I $(XEN_LIBXC)
CFLAGS  += -I $(XEN_XENSTORE)

SRCS    :=
SRCS    += main.c utils.c io.c

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(SRCS))
BIN      = consoled

all: $(BIN) xc_console

clean:
	$(RM) *.a *.so *.o *.rpm $(BIN) xc_console

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -L$(XEN_LIBXC) -L$(XEN_XENSTORE) \
              -lxc -lxenstore

xc_console: xc_console.o
	$(CC) $(CFLAGS) $^ -o $@ -L$(XEN_LIBXC) -L$(XEN_XENSTORE) \
	      -lxc -lxenstore

$(OBJS): $(HDRS)

install: $(BIN)
	$(INSTALL_DIR) -p $(DESTDIR)/$(CONSOLED_INSTALL_DIR)
	$(INSTALL_PROG) $(BIN) $(DESTDIR)/$(CONSOLED_INSTALL_DIR)
	$(INSTALL_DIR) -p $(DESTDIR)/$(XC_CONSOLE_INSTALL_DIR)
	$(INSTALL_PROG) xc_console $(DESTDIR)/$(XC_CONSOLE_INSTALL_DIR)
