XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_libxenstore)
CFLAGS += -include $(XEN_ROOT)/tools/config.h

LDLIBS += $(call xenlibs-ldlibs,ctrl store)
LDLIBS += $(SOCKET_LIBS)

OBJS-y := main.o

TARGETS := xenconsole

.PHONY: all
all: $(TARGETS)

xenconsole: $(OBJS-y)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS) $(APPEND_LDFLAGS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) xenconsole $(DESTDIR)$(LIBEXEC_BIN)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(LIBEXEC_BIN)/xenconsole

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) $(DEPS_RM)

.PHONY: distclean
distclean: clean

-include $(DEPS_INCLUDE)
