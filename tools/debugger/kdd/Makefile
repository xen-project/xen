XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += $(CFLAGS_libxenctrl)
LDLIBS  += $(LDLIBS_libxenctrl)

CFILES  := kdd.c kdd-xen.c
OBJS    := $(CFILES:.c=.o)

all: kdd

kdd: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

.PHONY: clean
clean:
	rm -f $(OBJS) $(DEPS) kdd

.PHONY: install
install: all
	[ -d $(DESTDIR)$(SBINDIR) ] || $(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) kdd $(DESTDIR)$(SBINDIR)/kdd
