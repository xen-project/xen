XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror
CFLAGS  += $(CFLAGS_libxenctrl)
CFLAGS  += -DXC_WANT_COMPAT_MAP_FOREIGN_API
LDLIBS  += $(LDLIBS_libxenctrl)

CFILES  := kdd.c kdd-xen.c
OBJS    := $(CFILES:.c=.o)

all: kdd

kdd: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(APPEND_LDFLAGS)

.PHONY: clean
clean:
	rm -f $(OBJS) $(DEPS) kdd

.PHONY: distclean
distclean: clean

.PHONY: install
install: all
	[ -d $(DESTDIR)$(sbindir) ] || $(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) kdd $(DESTDIR)$(sbindir)/kdd
