# Makefile for XCS
# Andrew Warfield, 2004

XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

XCS_INSTALL_DIR = /usr/sbin

INSTALL         = install
INSTALL_PROG    = $(INSTALL) -m0755
INSTALL_DIR     = $(INSTALL) -d -m0755

CC       = gcc
CFLAGS   = -Wall -Werror -g3 -D _XOPEN_SOURCE=600

CFLAGS  += -I $(XEN_XC)
CFLAGS  += -I $(XEN_LIBXC)
CFLAGS  += -I $(XEN_LIBXUTIL)

SRCS    :=
SRCS    += ctrl_interface.c
SRCS    += bindings.c
SRCS    += connection.c
SRCS    += evtchn.c
SRCS    += xcs.c

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(SRCS))
BIN      = xcs

all: $(BIN) xcsdump

clean:
	$(RM) *.a *.so *.o *.rpm $(BIN) xcsdump

xcsdump: xcsdump.c
	$(CC) $(CFLAGS) -o xcsdump xcsdump.c -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) \
              ctrl_interface.c evtchn.c  -lxc -lxutil

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -lxc -lxutil 

install: xcs xcsdump
	$(INSTALL_DIR) -p $(DESTDIR)/$(XCS_INSTALL_DIR)
	$(INSTALL_DIR) -p $(DESTDIR)/usr/include
	$(INSTALL_PROG) xcs $(DESTDIR)/$(XCS_INSTALL_DIR)
	$(INSTALL_PROG) xcsdump $(DESTDIR)/$(XCS_INSTALL_DIR)
	$(INSTALL_PROG) xcs_proto.h $(DESTDIR)/usr/include
