INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755
INSTALL_DATA	= $(INSTALL) -m0644

XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror -O3

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

BIN      = lomount

all: build
build: $(BIN)

install: build
	$(INSTALL_PROG) $(BIN) $(SCRIPTS) $(DESTDIR)/usr/bin

clean:
	$(RM) *.a *.so *.o *.rpm $(BIN)

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $< 

