
XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CLIENT_INSTALL_DIR = $(LIBDIR)/xen/bin

CFLAGS  += -Werror

CFLAGS  += -I $(XEN_LIBXC)
CFLAGS  += -I $(XEN_XENSTORE)

BIN      = xenconsoled xenconsole

.PHONY: all
all: $(BIN)

.PHONY: clean
clean:
	$(RM) *.a *.so *.o *.rpm $(BIN)
	$(RM) client/*.o daemon/*.o

xenconsoled: $(patsubst %.c,%.o,$(wildcard daemon/*.c))
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -L$(XEN_LIBXC) -L$(XEN_XENSTORE) \
              $(UTIL_LIBS) $(SOCKET_LIBS) -lxenctrl -lxenstore

xenconsole: $(patsubst %.c,%.o,$(wildcard client/*.c))
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -L$(XEN_LIBXC) -L$(XEN_XENSTORE) \
	      $(UTIL_LIBS) $(SOCKET_LIBS) -lxenctrl -lxenstore

.PHONY: install
install: $(BIN)
	$(INSTALL_DIR) $(DESTDIR)/$(SBINDIR)
	$(INSTALL_PROG) xenconsoled $(DESTDIR)/$(SBINDIR)
	$(INSTALL_DIR) $(DESTDIR)/$(CLIENT_INSTALL_DIR)
	$(INSTALL_PROG) xenconsole $(DESTDIR)/$(CLIENT_INSTALL_DIR)
