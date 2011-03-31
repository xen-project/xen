XEN_ROOT=$(CURDIR)/../../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror

CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_xeninclude) 

HDRS     = $(wildcard *.h)

.PHONY: all
all: xen-mceinj

install: 
	cp xen-mceinj /usr/sbin/

.PHONY: clean
clean:
	$(RM) *.o xen-mceinj

xen-mceinj: %: %.o Makefile
	$(CC) -o $@ $< $(LDFLAGS) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore)
