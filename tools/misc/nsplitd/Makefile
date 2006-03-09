XEN_ROOT := ../../..
include $(XEN_ROOT)/tools/Rules.mk

CFILES = $(wildcard *.c)

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

TARGET   = nsplitd

all: $(TARGET)

install: all

clean:
	$(RM) *.o $(TARGET) *~

$(TARGET): $(OBJS)
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $^

%.o: %.c $(HDRS) Makefile
	$(HOSTCC) $(HOSTCFLAGS) -c -o $@ $<
