
XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror

CFLAGS  += $(CFLAGS_libxenctrl)
CFLAGS  += $(CFLAGS_libxenstore)
LDLIBS += $(LDLIBS_libxenctrl)
LDLIBS += $(LDLIBS_libxenstore)
LDLIBS += $(UTIL_LIBS)
LDLIBS += $(SOCKET_LIBS)
LDLIBS += -lrt

BIN      = xenconsoled xenconsole

.PHONY: all
all: $(BIN)

.PHONY: clean
clean:
	$(RM) *.a *.so *.o *.rpm $(BIN) $(DEPS)
	$(RM) client/*.o daemon/*.o

xenconsoled: $(patsubst %.c,%.o,$(wildcard daemon/*.c))
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

xenconsole: $(patsubst %.c,%.o,$(wildcard client/*.c))
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

.PHONY: install
install: $(BIN)
	$(INSTALL_DIR) $(DESTDIR)/$(SBINDIR)
	$(INSTALL_PROG) xenconsoled $(DESTDIR)/$(SBINDIR)
	$(INSTALL_DIR) $(DESTDIR)$(PRIVATE_BINDIR)
	$(INSTALL_PROG) xenconsole $(DESTDIR)$(PRIVATE_BINDIR)

-include $(DEPS)
