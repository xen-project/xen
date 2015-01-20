XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

LDFLAGS=-static

.PHONY: all
all: console-dom0 console-domU procpipe

console-dom0: console-dom0.o
console-domU: console-domU.o
procpipe: procpipe.o

.PHONY: clean
clean: $(RM) *.o console-domU console-dom0 procpipe

.PHONY: distclean
distclean: clean
