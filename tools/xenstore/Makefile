XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR = 3.0
MINOR = 3

CFLAGS += -Werror
CFLAGS += -I.
# Include configure output (config.h)
CFLAGS += -include $(XEN_ROOT)/tools/config.h
CFLAGS += -I./include
CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += -DXEN_LIB_STORED="\"$(XEN_LIB_STORED)\""

CFLAGS-$(CONFIG_SYSTEMD)  += $(SYSTEMD_CFLAGS)
LDFLAGS-$(CONFIG_SYSTEMD) += $(SYSTEMD_LIBS)

CFLAGS  += $(CFLAGS-y)
LDFLAGS += $(LDFLAGS-y)

CLIENTS := xenstore-exists xenstore-list xenstore-read xenstore-rm xenstore-chmod
CLIENTS += xenstore-write xenstore-ls xenstore-watch

XENSTORED_OBJS = xenstored_core.o xenstored_watch.o xenstored_domain.o xenstored_transaction.o xs_lib.o talloc.o utils.o tdb.o hashtable.o

XENSTORED_OBJS_$(CONFIG_Linux) = xenstored_posix.o
XENSTORED_OBJS_$(CONFIG_SunOS) = xenstored_solaris.o xenstored_posix.o xenstored_probes.o
XENSTORED_OBJS_$(CONFIG_NetBSD) = xenstored_posix.o
XENSTORED_OBJS_$(CONFIG_FreeBSD) = xenstored_posix.o
XENSTORED_OBJS_$(CONFIG_MiniOS) = xenstored_minios.o

XENSTORED_OBJS += $(XENSTORED_OBJS_y)

ifneq ($(XENSTORE_STATIC_CLIENTS),y)
LIBXENSTORE := libxenstore.so
else
LIBXENSTORE := libxenstore.a
xenstore xenstore-control: CFLAGS += -static
endif

ALL_TARGETS = libxenstore.a clients
ifneq ($(nosharedlibs),y)
ALL_TARGETS += libxenstore.so
endif
ifeq ($(XENSTORE_XENSTORED),y)
ALL_TARGETS += xs_tdb_dump xenstored
endif

ifeq ($(CONFIG_Linux),y)
ALL_TARGETS += init-xenstore-domain
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

init-xenstore-domain.o: CFLAGS += $(CFLAGS_libxenguest)

init-xenstore-domain: init-xenstore-domain.o $(LIBXENSTORE)
	$(CC) $^ $(LDFLAGS) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore) -o $@ $(APPEND_LDFLAGS)

xenstored: $(XENSTORED_OBJS)
	$(CC) $^ $(LDFLAGS) $(LDLIBS_libxenctrl) $(SOCKET_LIBS) -o $@ $(APPEND_LDFLAGS)

xenstored.a: $(XENSTORED_OBJS)
	$(AR) cr $@ $^

$(CLIENTS): xenstore
	ln -f xenstore $@

xenstore: xenstore_client.o $(LIBXENSTORE)
	$(CC) $< $(LDFLAGS) $(LDLIBS_libxenstore) $(SOCKET_LIBS) -o $@ $(APPEND_LDFLAGS)

xenstore-control: xenstore_control.o $(LIBXENSTORE)
	$(CC) $< $(LDFLAGS) $(LDLIBS_libxenstore) $(SOCKET_LIBS) -o $@ $(APPEND_LDFLAGS)

xs_tdb_dump: xs_tdb_dump.o utils.o tdb.o talloc.o
	$(CC) $^ $(LDFLAGS) -o $@ $(APPEND_LDFLAGS)

libxenstore.so: libxenstore.so.$(MAJOR)
	ln -sf $< $@
libxenstore.so.$(MAJOR): libxenstore.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

xs.opic: CFLAGS += -DUSE_PTHREAD

libxenstore.so.$(MAJOR).$(MINOR): xs.opic xs_lib.opic
	$(CC) $(LDFLAGS) $(PTHREAD_LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenstore.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(SOCKET_LIBS) $(PTHREAD_LIBS) $(APPEND_LDFLAGS)

libxenstore.a: xs.o xs_lib.o
	$(AR) rcs $@ $^

.PHONY: clean
clean:
	rm -f *.a *.o *.opic *.so* xenstored_probes.h
	rm -f xenstored xs_random xs_stress xs_crashme
	rm -f xs_tdb_dump xenstore-control init-xenstore-domain
	rm -f xenstore $(CLIENTS)
	$(RM) $(DEPS)

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
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)/xenstore-compat
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
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_SHLIB) libxenstore.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	ln -sf libxenstore.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxenstore.so.$(MAJOR)
	ln -sf libxenstore.so.$(MAJOR) $(DESTDIR)$(libdir)/libxenstore.so
	$(INSTALL_DATA) libxenstore.a $(DESTDIR)$(libdir)
	$(INSTALL_DATA) include/xenstore.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) include/xenstore_lib.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) include/compat/xs.h $(DESTDIR)$(includedir)/xenstore-compat/xs.h
	$(INSTALL_DATA) include/compat/xs_lib.h $(DESTDIR)$(includedir)/xenstore-compat/xs_lib.h
	ln -sf xenstore-compat/xs.h  $(DESTDIR)$(includedir)/xs.h
	ln -sf xenstore-compat/xs_lib.h $(DESTDIR)$(includedir)/xs_lib.h

.PHONY: clients-install
clients-install: clients
	$(INSTALL_DIR) $(DESTDIR)$(bindir)
	$(INSTALL_PROG) xenstore $(DESTDIR)$(bindir)
	set -e ; for c in $(CLIENTS) ; do \
		ln -f $(DESTDIR)$(bindir)/xenstore $(DESTDIR)$(bindir)/$${c} ; \
	done

-include $(DEPS)

# never delete any intermediate files.
.SECONDARY:
