# Makefile for XCS
# Andrew Warfield, 2004

XEN_ROOT=../..
include $(XEN_ROOT)/tools/Make.defs

XCS_INSTALL_DIR = /usr/sbin

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
	$(RM) *.a *.so *.o *.rpm $(BIN) ctrl_dump

xcsdump: xcsdump.c
	$(CC) $(CFLAGS) -o xcsdump xcsdump.c -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) \
              ctrl_interface.c evtchn.c  -lxc -lxutil

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -lxc -lxutil 

install: xcs xcsdump
	mkdir -p $(prefix)/$(XCS_INSTALL_DIR)
	mkdir -p $(prefix)/usr/include
	install -m0755 xcs $(prefix)/$(XCS_INSTALL_DIR)
	install -m0755 xcsdump $(prefix)/$(XCS_INSTALL_DIR)
	install -m0644 xcs_proto.h $(prefix)/usr/include
