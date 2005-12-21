
XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test_x86_emulator

CC     := gcc
CFLAGS := -O2 -Wall -Werror -D__TEST_HARNESS__

all: $(TARGET)

$(TARGET): x86_emulate.o test_x86_emulator.o
	$(CC) -o $@ $^

clean:
	rm -rf $(TARGET) *.o *~ core

install:

x86_emulate.o: $(XEN_ROOT)/xen/arch/x86/x86_emulate.c
	$(CC) $(CFLAGS) -I$(XEN_ROOT)/xen/include -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -I$(XEN_ROOT)/xen/include -c -o $@ $<
