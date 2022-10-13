XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_libxenstore)
CFLAGS += $(CFLAGS_libxenevtchn)
CFLAGS += $(CFLAGS_libxengnttab)
CFLAGS += $(CFLAGS_libxenforeignmemory)
CFLAGS-$(CONFIG_ARM) += -DCONFIG_ARM
CFLAGS += -include $(XEN_ROOT)/tools/config.h

LDLIBS += $(call xenlibs-ldlibs,ctrl store evtchn gnttab foreignmemory)
LDLIBS += $(SOCKET_LIBS)
LDLIBS += $(UTIL_LIBS)
LDLIBS += -lrt

OBJS-y := main.o
OBJS-y += io.o
OBJS-y += utils.o

TARGETS := xenconsoled

.PHONY: all
all: $(TARGETS)

xenconsoled: $(OBJS-y)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS) $(APPEND_LDFLAGS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)/$(sbindir)
	$(INSTALL_PROG) xenconsoled $(DESTDIR)/$(sbindir)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(sbindir)/xenconsoled

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) $(DEPS_RM)

.PHONY: distclean
distclean: clean

-include $(DEPS_INCLUDE)
