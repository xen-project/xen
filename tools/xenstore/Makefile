XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk
XEN_LIBXC          = $(XEN_ROOT)/tools/libxc

MAJOR = 3.0
MINOR = 0

PROFILE=#-pg
BASECFLAGS=-Werror
# Make gcc generate dependencies.
BASECFLAGS += -Wp,-MD,.$(@F).d
PROG_DEP = .*.d
BASECFLAGS+= $(PROFILE)
BASECFLAGS+= $(CFLAGS_libxenctrl)
BASECFLAGS+= -I.

CFLAGS  += $(BASECFLAGS)
LDFLAGS += $(PROFILE)

CLIENTS := xenstore-exists xenstore-list xenstore-read xenstore-rm xenstore-chmod
CLIENTS += xenstore-write
CLIENTS_OBJS := $(patsubst xenstore-%,xenstore_%.o,$(CLIENTS))

XENSTORED_OBJS = xenstored_core.o xenstored_watch.o xenstored_domain.o xenstored_transaction.o xs_lib.o talloc.o utils.o tdb.o hashtable.o

XENSTORED_OBJS_$(CONFIG_Linux) = xenstored_linux.o
XENSTORED_OBJS_$(CONFIG_SunOS) = xenstored_solaris.o xenstored_probes.o
XENSTORED_OBJS_$(CONFIG_NetBSD) = xenstored_netbsd.o

XENSTORED_OBJS += $(XENSTORED_OBJS_y)

.PHONY: all
all: libxenstore.so libxenstore.a xenstored $(CLIENTS) xs_tdb_dump xenstore-control xenstore-ls

ifeq ($(CONFIG_SunOS),y)
xenstored_probes.h: xenstored_probes.d
	dtrace -C -h -s xenstored_probes.d

xenstored_solaris.o: xenstored_probes.h

xenstored_probes.o: xenstored_solaris.o
	dtrace -C -G -s xenstored_probes.d xenstored_solaris.o 

CFLAGS += -DHAVE_DTRACE=1
endif
 
xenstored: $(XENSTORED_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) $(LDFLAGS_libxenctrl) $(SOCKET_LIBS) -o $@

$(CLIENTS): xenstore-%: xenstore_%.o libxenstore.so
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LOADLIBES) $(LDLIBS) -L. -lxenstore $(SOCKET_LIBS) -o $@

$(CLIENTS_OBJS): xenstore_%.o: xenstore_client.c
	$(COMPILE.c) -DCLIENT_$(*F) -o $@ $<

xenstore-control: xenstore_control.o libxenstore.so
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LOADLIBES) $(LDLIBS) -L. -lxenstore $(SOCKET_LIBS) -o $@

xenstore-ls: xsls.o libxenstore.so
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LOADLIBES) $(LDLIBS) -L. -lxenstore $(SOCKET_LIBS) -o $@

xs_tdb_dump: xs_tdb_dump.o utils.o tdb.o talloc.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

libxenstore.so: libxenstore.so.$(MAJOR)
	ln -sf $< $@
libxenstore.so.$(MAJOR): libxenstore.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenstore.so.$(MAJOR).$(MINOR): xs.opic xs_lib.opic
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenstore.so.$(MAJOR) $(SHLIB_CFLAGS) -o $@ $^ $(SOCKET_LIBS) -lpthread

libxenstore.a: xs.o xs_lib.o
	$(AR) rcs libxenstore.a $^

.PHONY: clean
clean:
	rm -f *.a *.o *.opic *.so* xenstored_probes.h
	rm -f xenstored xs_random xs_stress xs_crashme
	rm -f xs_tdb_dump xenstore-control xenstore-ls
	rm -f $(CLIENTS)
	$(RM) $(PROG_DEP)

.PHONY: TAGS
TAGS:
	etags `find . -name '*.[ch]'`

.PHONY: tarball
tarball: clean
	cd .. && tar -c -j -v -h -f xenstore.tar.bz2 xenstore/

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)/var/run/xenstored
	$(INSTALL_DIR) $(DESTDIR)/var/lib/xenstored
	$(INSTALL_DIR) $(DESTDIR)$(BINDIR)
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_DIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_PROG) xenstored $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) $(CLIENTS) $(DESTDIR)$(BINDIR)
	$(INSTALL_PROG) xenstore-control $(DESTDIR)$(BINDIR)
	$(INSTALL_PROG) xenstore-ls $(DESTDIR)$(BINDIR)
	$(INSTALL_DIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_PROG) libxenstore.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)
	ln -sf libxenstore.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libxenstore.so.$(MAJOR)
	ln -sf libxenstore.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libxenstore.so
	$(INSTALL_DATA) libxenstore.a $(DESTDIR)$(LIBDIR)
	$(INSTALL_DATA) xs.h $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) xs_lib.h $(DESTDIR)$(INCLUDEDIR)

-include $(PROG_DEP)

# never delete any intermediate files.
.SECONDARY:
