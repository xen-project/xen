
CC     = gcc
CFLAGS = -Wall -O3
CFILES = $(wildcard *.c)

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

TARGET   = nsplitd

all: $(TARGET)

install: all

clean:
	$(RM) *.o $(TARGET) *~

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -c -o $@ $<
