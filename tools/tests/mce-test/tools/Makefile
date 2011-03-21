XEN_ROOT=$(CURDIR)/../../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror

CFLAGS += -I $(XEN_XC)
CFLAGS += -I $(XEN_LIBXC)
CFLAGS += -I $(XEN_INCLUDE)

HDRS     = $(wildcard *.h)

.PHONY: all
all: xen-mceinj

install: 
	cp xen-mceinj /usr/sbin/

.PHONY: clean
clean:
	$(RM) *.o xen-mceinj

%.o: %.c $(HDRS) Makefile
	$(CC) -c $(CFLAGS) -o $@ $<

xen-mceinj: %: %.o Makefile
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore)
