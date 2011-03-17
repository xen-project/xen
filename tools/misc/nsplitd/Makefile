XEN_ROOT := $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFILES = $(wildcard *.c)

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

TARGET   = nsplitd

.PHONY: all
all: $(TARGET)

.PHONY: install
install: all

.PHONY: clean
clean:
	$(RM) *.o $(TARGET) *~

$(TARGET): $(OBJS)
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $^

%.o: %.c $(HDRS) Makefile
	$(HOSTCC) $(HOSTCFLAGS) -c -o $@ $<
