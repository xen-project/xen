
XEN_ROOT=../..
include $(XEN_ROOT)/tools/Make.defs

CC       = gcc
CFLAGS   = -Wall -Werror -O3

CFLAGS  += -I $(XEN_LINUX_INCLUDE)
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
	mkdir -p $(prefix)/usr/bin
	mkdir -p $(prefix)/usr/man/man1
	mkdir -p $(prefix)/usr/man/man8
	install -m0755 $(BIN) $(SCRIPTS) $(prefix)/usr/bin
	install -m0644 $(MAN1) $(prefix)/usr/man/man1
	install -m0644 $(MAN8) $(prefix)/usr/man/man8

clean:
	$(RM) *.a *.so *.o *.rpm $(BIN)

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $< -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -lxc -lxutil
