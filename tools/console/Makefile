
XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror

CFLAGS  += $(CFLAGS_libxenctrl)
CFLAGS  += -I $(XEN_XENSTORE)
LDFLAGS += $(LDFLAGS_libxenctrl)

BIN      = xenconsoled xenconsole

.PHONY: all
all: $(BIN)

.PHONY: clean
clean:
	$(RM) *.a *.so *.o *.rpm $(BIN)
	$(RM) client/*.o daemon/*.o

xenconsoled: $(patsubst %.c,%.o,$(wildcard daemon/*.c))
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -L$(XEN_XENSTORE) \
              $(UTIL_LIBS) $(SOCKET_LIBS) -lxenstore

xenconsole: $(patsubst %.c,%.o,$(wildcard client/*.c))
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -L$(XEN_XENSTORE) \
	      $(UTIL_LIBS) $(SOCKET_LIBS) -lxenstore

.PHONY: install
install: $(BIN)
	$(INSTALL_DIR) $(DESTDIR)/$(SBINDIR)
	$(INSTALL_PROG) xenconsoled $(DESTDIR)/$(SBINDIR)
	$(INSTALL_DIR) $(DESTDIR)$(PRIVATE_BINDIR)
	$(INSTALL_PROG) xenconsole $(DESTDIR)$(PRIVATE_BINDIR)
