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
CFLAGS += $(CFLAGS_libxentoolcore)
CFLAGS += -DXEN_LIB_STORED="\"$(XEN_LIB_STORED)\""
CFLAGS += -DXEN_RUN_STORED="\"$(XEN_RUN_STORED)\""

CFLAGS-$(CONFIG_SYSTEMD)  += $(SYSTEMD_CFLAGS)
LDFLAGS-$(CONFIG_SYSTEMD) += $(SYSTEMD_LIBS)

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

$(XENSTORED_OBJS): CFLAGS += $(CFLAGS_libxengnttab)

xenstored: $(XENSTORED_OBJS)
	$(CC) $^ $(LDFLAGS) $(LDLIBS_libxenevtchn) $(LDLIBS_libxengnttab) $(LDLIBS_libxenctrl) $(LDLIBS_xenstored) $(SOCKET_LIBS) -o $@ $(APPEND_LDFLAGS)

xenstored.a: $(XENSTORED_OBJS)
	$(AR) cr $@ $^

$(CLIENTS): xenstore
	ln -f xenstore $@

xenstore: xenstore_client.o $(LIBXENSTORE)
	$(CC) $< $(LDFLAGS) $(LDLIBS_libxenstore) $(LDLIBS_libxentoolcore) $(SOCKET_LIBS) -o $@ $(APPEND_LDFLAGS)

xenstore-control: xenstore_control.o $(LIBXENSTORE)
	$(CC) $< $(LDFLAGS) $(LDLIBS_libxenstore) $(LDLIBS_libxentoolcore) $(SOCKET_LIBS) -o $@ $(APPEND_LDFLAGS)

xs_tdb_dump: xs_tdb_dump.o utils.o tdb.o talloc.o
	$(CC) $^ $(LDFLAGS) -o $@ $(APPEND_LDFLAGS)

libxenstore.so: libxenstore.so.$(MAJOR)
	ln -sf $< $@
libxenstore.so.$(MAJOR): libxenstore.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

xs.opic: CFLAGS += -DUSE_PTHREAD

libxenstore.so.$(MAJOR).$(MINOR): xs.opic xs_lib.opic
	$(CC) $(LDFLAGS) $(PTHREAD_LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenstore.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(LDLIBS_libxentoolcore) $(SOCKET_LIBS) $(PTHREAD_LIBS) $(APPEND_LDFLAGS)

libxenstore.a: xs.o xs_lib.o
	$(AR) rcs $@ $^

PKG_CONFIG := xenstore.pc
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(foreach pc,$(PKG_CONFIG),$(PKG_CONFIG_DIR)/$(pc))

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_XENSTORE)/include
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_CFLAGS_LOCAL = $(CFLAGS_xeninclude)

$(LIBXENSTORE): $(PKG_CONFIG_INST) $(PKG_CONFIG_LOCAL)

.PHONY: clean
clean:
	rm -f *.a *.o *.opic *.so* xenstored_probes.h
	rm -f xenstored xs_random xs_stress xs_crashme
	rm -f xs_tdb_dump xenstore-control init-xenstore-domain
	rm -f xenstore $(CLIENTS)
	rm -f xenstore.pc
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
	$(INSTALL_DATA) xenstore.pc $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/xenstore.pc
	rm -f $(DESTDIR)$(includedir)/xs_lib.h
	rm -f $(DESTDIR)$(includedir)/xs.h
	rm -f $(DESTDIR)$(includedir)/xenstore-compat/xs_lib.h
	rm -f $(DESTDIR)$(includedir)/xenstore-compat/xs.h
	rm -f $(DESTDIR)$(includedir)/xenstore_lib.h
	rm -f $(DESTDIR)$(includedir)/xenstore.h
	rm -f $(DESTDIR)$(libdir)/libxenstore.a
	rm -f $(DESTDIR)$(libdir)/libxenstore.so
	rm -f $(DESTDIR)$(libdir)/libxenstore.so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/libxenstore.so.$(MAJOR).$(MINOR)
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
