
XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

DAEMON_INSTALL_DIR = /usr/sbin
CLIENT_INSTALL_DIR = /usr/$(LIBDIR)/xen/bin

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
	$(CC) $(CFLAGS) $^ -o $@ -L$(XEN_LIBXC) -L$(XEN_XENSTORE) \
              $(SOCKET_LIBS) -lxenctrl -lxenstore

xenconsole: $(patsubst %.c,%.o,$(wildcard client/*.c))
	$(CC) $(CFLAGS) $^ -o $@ -L$(XEN_LIBXC) -L$(XEN_XENSTORE) \
	      $(SOCKET_LIBS) -lxenctrl -lxenstore

.PHONY: install
install: $(BIN)
	$(INSTALL_DIR) $(DESTDIR)/$(DAEMON_INSTALL_DIR)
	$(INSTALL_PROG) xenconsoled $(DESTDIR)/$(DAEMON_INSTALL_DIR)
	$(INSTALL_DIR) $(DESTDIR)/$(CLIENT_INSTALL_DIR)
	$(INSTALL_PROG) xenconsole $(DESTDIR)/$(CLIENT_INSTALL_DIR)
