XEN_ROOT=../..
include $(XEN_ROOT)/tools/Make.defs

CC       = gcc
CFLAGS   = -Wall -Werror -g

CFLAGS  += -I $(XEN_XC)
CFLAGS  += -I $(XEN_LIBXC)
CFLAGS  += -I $(XEN_LIBXUTIL)

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

BIN      = minixend

all: $(BIN)

clean:
	$(RM) *.a *.so *.o *.rpm $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -L$(XEN_LIBXC) -L$(XEN_LIBXUTIL) -lxc -lxutil -lpthread
