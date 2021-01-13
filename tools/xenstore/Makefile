XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR = 3.0
MINOR = 3

CFLAGS += -Werror
CFLAGS += -I.
# Include configure output (config.h)
CFLAGS += -include $(XEN_ROOT)/tools/config.h
CFLAGS += -I./include
CFLAGS += $(CFLAGS_libxenevtchn)
CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_libxenguest)
CFLAGS += $(CFLAGS_libxentoolcore)
CFLAGS += -DXEN_LIB_STORED="\"$(XEN_LIB_STORED)\""
CFLAGS += -DXEN_RUN_STORED="\"$(XEN_RUN_STORED)\""

CFLAGS  += $(CFLAGS-y)
LDFLAGS += $(LDFLAGS-y)

CLIENTS := xenstore-exists xenstore-list xenstore-read xenstore-rm xenstore-chmod
CLIENTS += xenstore-write xenstore-ls xenstore-watch

XENSTORED_OBJS = xenstored_core.o xenstored_watch.o xenstored_domain.o
XENSTORED_OBJS += xenstored_transaction.o xenstored_control.o
XENSTORED_OBJS += xs_lib.o talloc.o utils.o tdb.o hashtable.o

XENSTORED_OBJS_$(CONFIG_Linux) = xenstored_posix.o
XENSTORED_OBJS_$(CONFIG_SunOS) = xenstored_solaris.o xenstored_posix.o xenstored_probes.o
XENSTORED_OBJS_$(CONFIG_NetBSD) = xenstored_posix.o
XENSTORED_OBJS_$(CONFIG_FreeBSD) = xenstored_posix.o
XENSTORED_OBJS_$(CONFIG_MiniOS) = xenstored_minios.o

XENSTORED_OBJS += $(XENSTORED_OBJS_y)
LDLIBS_xenstored += -lrt

ALL_TARGETS = clients
ifeq ($(XENSTORE_XENSTORED),y)
ALL_TARGETS += xs_tdb_dump xenstored
endif

ifdef CONFIG_STUBDOM
CFLAGS += -DNO_SOCKETS=1
endif

.PHONY: all
all: $(ALL_TARGETS)

.PHONY: clients
clients: xenstore $(CLIENTS) xenstore-control

ifeq ($(CONFIG_SunOS),y)
xenstored_probes.h: xenstored_probes.d
	dtrace -C -h -s xenstored_probes.d

xenstored_solaris.o: xenstored_probes.h

xenstored_probes.o: xenstored_solaris.o
	dtrace -C -G -s xenstored_probes.d xenstored_solaris.o 

CFLAGS += -DHAVE_DTRACE=1
endif

ifeq ($(CONFIG_SYSTEMD),y)
$(XENSTORED_OBJS): CFLAGS += $(SYSTEMD_CFLAGS)
xenstored: LDFLAGS += $(SYSTEMD_LIBS)
endif

$(XENSTORED_OBJS): CFLAGS += $(CFLAGS_libxengnttab)

xenstored: $(XENSTORED_OBJS)
	$(CC) $^ $(LDFLAGS) $(LDLIBS_libxenevtchn) $(LDLIBS_libxengnttab) $(LDLIBS_libxenctrl) $(LDLIBS_xenstored) $(SOCKET_LIBS) -o $@ $(APPEND_LDFLAGS)

xenstored.a: $(XENSTORED_OBJS)
	$(AR) cr $@ $^

$(CLIENTS): xenstore
	ln -f xenstore $@

xenstore: xenstore_client.o
	$(CC) $< $(LDFLAGS) $(LDLIBS_libxenstore) $(LDLIBS_libxentoolcore) $(SOCKET_LIBS) -o $@ $(APPEND_LDFLAGS)

xenstore-control: xenstore_control.o
	$(CC) $< $(LDFLAGS) $(LDLIBS_libxenstore) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxentoolcore) $(SOCKET_LIBS) -o $@ $(APPEND_LDFLAGS)

xs_tdb_dump: xs_tdb_dump.o utils.o tdb.o talloc.o
	$(CC) $^ $(LDFLAGS) -o $@ $(APPEND_LDFLAGS)

.PHONY: clean
clean:
	rm -f *.a *.o xenstored_probes.h
	rm -f xenstored xs_random xs_stress xs_crashme
	rm -f xs_tdb_dump xenstore-control init-xenstore-domain
	rm -f xenstore $(CLIENTS)
	$(RM) $(DEPS_RM)

.PHONY: distclean
distclean: clean

.PHONY: TAGS
TAGS:
	etags `find . -name '*.[ch]'`

.PHONY: tarball
tarball: clean
	cd .. && tar -c -j -v -h -f xenstore.tar.bz2 xenstore/

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

# never delete any intermediate files.
.SECONDARY:
