XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

LDFLAGS=-static

all: console-dom0 console-domU procpipe

console-dom0: console-dom0.o
console-domU: console-domU.o
procpipe: procpipe.o

clean:; $(RM) *.o console-domU console-dom0 procpipe
