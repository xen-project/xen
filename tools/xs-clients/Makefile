XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -include $(XEN_ROOT)/tools/config.h
CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_libxenguest)
CFLAGS += $(CFLAGS_libxentoolcore)
CFLAGS += $(CFLAGS_libxenstore)

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

.PHONY: all
all: $(TARGETS)

.PHONY: clients
clients: xenstore $(CLIENTS) xenstore-control

$(CLIENTS): xenstore
	ln -f xenstore $@

xenstore: xenstore_client.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@ $(APPEND_LDFLAGS)

xenstore-control: xenstore_control.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@ $(APPEND_LDFLAGS)

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) $(DEPS_RM)

.PHONY: distclean
distclean: clean

.PHONY: TAGS
TAGS:
	etags `find . -name '*.[ch]'`

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(bindir)
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
	if [ -d $(DESTDIR)$(includedir)/xenstore-compat ]; then \
		rmdir --ignore-fail-on-non-empty $(DESTDIR)$(includedir)/xenstore-compat; \
	fi

-include $(DEPS_INCLUDE)
