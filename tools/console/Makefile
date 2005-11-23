
XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

DAEMON_INSTALL_DIR = /usr/sbin
CLIENT_INSTALL_DIR = /usr/$(LIBDIR)/xen/bin

INSTALL         = install
INSTALL_PROG    = $(INSTALL) -m0755
INSTALL_DIR     = $(INSTALL) -d -m0755

CFLAGS  += -Wall -Werror -ggdb3 -O0

CFLAGS  += -I $(XEN_LIBXC)
CFLAGS  += -I $(XEN_XENSTORE)

BIN      = xenconsoled xenconsole

all: $(BIN)

clean:
	$(RM) *.a *.so *.o *.rpm $(BIN)
	$(RM) client/*.o daemon/*.o

xenconsoled: $(patsubst %.c,%.o,$(wildcard daemon/*.c))
	$(CC) $(CFLAGS) $^ -o $@ -L$(XEN_LIBXC) -L$(XEN_XENSTORE) \
              -lxenctrl -lxenstore

xenconsole: $(patsubst %.c,%.o,$(wildcard client/*.c))
	$(CC) $(CFLAGS) $^ -o $@ -L$(XEN_LIBXC) -L$(XEN_XENSTORE) \
	      -lxenctrl -lxenstore

install: $(BIN)
	$(INSTALL_DIR) -p $(DESTDIR)/$(DAEMON_INSTALL_DIR)
	$(INSTALL_PROG) xenconsoled $(DESTDIR)/$(DAEMON_INSTALL_DIR)
	$(INSTALL_DIR) -p $(DESTDIR)/$(CLIENT_INSTALL_DIR)
	$(INSTALL_PROG) xenconsole $(DESTDIR)/$(CLIENT_INSTALL_DIR)
