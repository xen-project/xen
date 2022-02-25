XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

include Makefile.common

xenstored: LDLIBS += $(LDLIBS_libxenevtchn)
xenstored: LDLIBS += $(LDLIBS_libxengnttab)
xenstored: LDLIBS += $(LDLIBS_libxenctrl)
xenstored: LDLIBS += -lrt
xenstored: LDLIBS += $(SOCKET_LIBS)

ifeq ($(CONFIG_SYSTEMD),y)
$(XENSTORED_OBJS-y): CFLAGS += $(SYSTEMD_CFLAGS)
xenstored: LDLIBS += $(SYSTEMD_LIBS)
endif

xenstore: LDLIBS += $(LDLIBS_libxenstore)
xenstore: LDLIBS += $(LDLIBS_libxentoolcore)
xenstore: LDLIBS += $(SOCKET_LIBS)

xenstore-control: LDLIBS += $(LDLIBS_libxenstore)
xenstore-control: LDLIBS += $(LDLIBS_libxenctrl)
xenstore-control: LDLIBS += $(LDLIBS_libxenguest)
xenstore-control: LDLIBS += $(LDLIBS_libxentoolcore)
xenstore-control: LDLIBS += $(SOCKET_LIBS)

CLIENTS := xenstore-exists xenstore-list xenstore-read xenstore-rm xenstore-chmod
CLIENTS += xenstore-write xenstore-ls xenstore-watch

TARGETS := xenstore $(CLIENTS) xenstore-control
ifeq ($(XENSTORE_XENSTORED),y)
TARGETS += xs_tdb_dump xenstored
endif

.PHONY: all
all: $(TARGETS)

.PHONY: clients
clients: xenstore $(CLIENTS) xenstore-control

xenstored: $(XENSTORED_OBJS-y)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@ $(APPEND_LDFLAGS)

$(CLIENTS): xenstore
	ln -f xenstore $@

xenstore: xenstore_client.o xs_lib.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@ $(APPEND_LDFLAGS)

xenstore-control: xenstore_control.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@ $(APPEND_LDFLAGS)

xs_tdb_dump: xs_tdb_dump.o utils.o tdb.o talloc.o
	$(CC) $(LDFLAGS) $^ -o $@ $(APPEND_LDFLAGS)

.PHONY: clean
clean::
	$(RM) $(TARGETS) $(DEPS_RM)

.PHONY: distclean
distclean: clean

.PHONY: TAGS
TAGS:
	etags `find . -name '*.[ch]'`

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(bindir)
ifeq ($(XENSTORE_XENSTORED),y)
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_DIR) $(DESTDIR)$(XEN_LIB_STORED)
	$(INSTALL_PROG) xenstored $(DESTDIR)$(sbindir)
endif
	$(INSTALL_PROG) xenstore-control $(DESTDIR)$(bindir)
	$(INSTALL_PROG) xenstore $(DESTDIR)$(bindir)
	set -e ; for c in $(CLIENTS) ; do \
		ln -f $(DESTDIR)$(bindir)/xenstore $(DESTDIR)$(bindir)/$${c} ; \
	done

.PHONY: uninstall
uninstall:
	rm -f $(addprefix $(DESTDIR)$(bindir)/, $(CLIENTS))
	rm -f $(DESTDIR)$(bindir)/xenstore
	rm -f $(DESTDIR)$(bindir)/xenstore-control
ifeq ($(XENSTORE_XENSTORED),y)
	rm -f $(DESTDIR)$(sbindir)/xenstored
	if [ -d $(DESTDIR)$(XEN_LIB_STORED) ]; then \
		rmdir --ignore-fail-on-non-empty $(DESTDIR)$(XEN_LIB_STORED); \
	fi
endif
	if [ -d $(DESTDIR)$(includedir)/xenstore-compat ]; then \
		rmdir --ignore-fail-on-non-empty $(DESTDIR)$(includedir)/xenstore-compat; \
	fi

.PHONY: clients-uninstall
clients-uninstall:
	rm -f $(addprefix $(DESTDIR)$(bindir)/, $(CLIENTS))

.PHONY: clients-install
clients-install: clients
	$(INSTALL_DIR) $(DESTDIR)$(bindir)
	$(INSTALL_PROG) xenstore $(DESTDIR)$(bindir)
	set -e ; for c in $(CLIENTS) ; do \
		ln -f $(DESTDIR)$(bindir)/xenstore $(DESTDIR)$(bindir)/$${c} ; \
	done

-include $(DEPS_INCLUDE)
