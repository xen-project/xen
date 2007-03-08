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
#BASECFLAGS+= -I$(XEN_ROOT)/tools
BASECFLAGS+= -I$(XEN_ROOT)/tools/libxc
BASECFLAGS+= -I.

CFLAGS  += $(BASECFLAGS)
LDFLAGS += $(PROFILE) -L$(XEN_LIBXC)
TESTDIR  = testsuite/tmp
TESTFLAGS= -DTESTING
TESTENV  = XENSTORED_ROOTDIR=$(TESTDIR) XENSTORED_RUNDIR=$(TESTDIR)

CLIENTS := xenstore-exists xenstore-list xenstore-read xenstore-rm xenstore-chmod
CLIENTS += xenstore-write
CLIENTS_OBJS := $(patsubst xenstore-%,xenstore_%.o,$(CLIENTS))

XENSTORED_OBJS = xenstored_core.o xenstored_watch.o xenstored_domain.o xenstored_transaction.o xs_lib.o talloc.o utils.o tdb.o hashtable.o

XENSTORED_OBJS_$(CONFIG_Linux) = xenstored_linux.o
XENSTORED_OBJS_$(CONFIG_SunOS) = xenstored_solaris.o

XENSTORED_OBJS += $(XENSTORED_OBJS_y)

.PHONY: all
all: libxenstore.so libxenstore.a xenstored $(CLIENTS) xs_tdb_dump xenstore-control xenstore-ls

test_interleaved_transactions: test_interleaved_transactions.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -L. -lxenstore -o $@

.PHONY: testcode
testcode: xs_test xenstored_test xs_random

xenstored: $(XENSTORED_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -lxenctrl $(SOCKET_LIBS) -o $@

$(CLIENTS): xenstore-%: xenstore_%.o libxenstore.so
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LOADLIBES) $(LDLIBS) -L. -lxenstore $(SOCKET_LIBS) -o $@

$(CLIENTS_OBJS): xenstore_%.o: xenstore_client.c
	$(COMPILE.c) -DCLIENT_$(*F) -o $@ $<

xenstore-control: xenstore_control.o libxenstore.so
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LOADLIBES) $(LDLIBS) -L. -lxenstore $(SOCKET_LIBS) -o $@

xenstore-ls: xsls.o libxenstore.so
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LOADLIBES) $(LDLIBS) -L. -lxenstore $(SOCKET_LIBS) -o $@

xenstored_test: xenstored_core_test.o xenstored_watch_test.o xenstored_domain_test.o xenstored_transaction_test.o xs_lib.o talloc_test.o fake_libxc.o utils.o tdb.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

xs_tdb_dump: xs_tdb_dump.o utils.o tdb.o talloc.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

xs_test xs_random xs_stress xs_crashme: LDFLAGS+=-lpthread
xs_test: xs_test.o xs_lib.o utils.o
xs_random: xs_random.o xs_test_lib.o xs_lib.o talloc.o utils.o
xs_stress: xs_stress.o xs_test_lib.o xs_lib.o talloc.o utils.o
xs_crashme: xs_crashme.o xs_lib.o talloc.o utils.o

speedtest: speedtest.o xs.o xs_lib.o utils.o talloc.o

.PHONY: check-speed
check-speed: speedtest xenstored_test $(TESTDIR)
	$(TESTENV) time ./speedtest 100

xs_test.o xs_stress.o xenstored_core_test.o xenstored_watch_test.o xenstored_transaction_test.o xenstored_domain_test.o xs_random.o xs_test_lib.o talloc_test.o fake_libxc.o xs_crashme.o: CFLAGS=$(BASECFLAGS) $(TESTFLAGS)

xenstored_%_test.o: xenstored_%.c
	$(COMPILE.c) -o $@ $<

xs_test_lib.o: xs.c
	$(COMPILE.c) -o $@ $<

talloc_test.o: talloc.c
	$(COMPILE.c) -o $@ $<

libxenstore.so: libxenstore.so.$(MAJOR)
	ln -sf $< $@
libxenstore.so.$(MAJOR): libxenstore.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenstore.so.$(MAJOR).$(MINOR): xs.opic xs_lib.opic
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenstore.so.$(MAJOR) $(SHLIB_CFLAGS) -o $@ $^ $(SOCKET_LIBS) -lpthread

libxenstore.a: xs.o xs_lib.o
	$(AR) rcs libxenstore.a $^

.PHONY: clean
clean: testsuite-clean
	rm -f *.a *.o *.opic *.so*
	rm -f xenstored xs_random xs_stress xs_crashme
	rm -f xs_test xenstored_test xs_tdb_dump xenstore-control xenstore-ls
	rm -f $(CLIENTS)
	$(RM) $(PROG_DEP)

.PHONY: print-dir
print-dir:
	@echo -n tools/xenstore: 

.PHONY: print-end
print-end:
	@echo

.PHONY: check
check: print-dir testsuite-fast randomcheck-fast print-end

.PHONY: fullcheck
fullcheck: testsuite-run randomcheck stresstest

$(TESTDIR):
	mkdir $@

.PHONY: testsuite-run
testsuite-run: xenstored_test xs_test $(TESTDIR)
	$(TESTENV) testsuite/test.sh && echo

.PHONY: testsuite-fast
testsuite-fast: xenstored_test xs_test $(TESTDIR)
	@$(TESTENV) testsuite/test.sh --fast

.PHONY: testsuite-clean
testsuite-clean:
	rm -rf $(TESTDIR)

# Make this visible so they can see repeat tests without --fast if they
# fail.
RANDSEED=$(shell date +%s)
.PHONY: randomcheck
randomcheck: xs_random xenstored_test $(TESTDIR)
	$(TESTENV) ./xs_random --simple --fast /tmp/xs_random 200000 $(RANDSEED) && echo
	$(TESTENV) ./xs_random --fast /tmp/xs_random 100000 $(RANDSEED) && echo
#	$(TESTENV) ./xs_random --fail /tmp/xs_random 10000 $(RANDSEED)

.PHONY: crashme
crashme:  xs_crashme xenstored_test $(TESTDIR)
	rm -rf $(TESTDIR)/store $(TESTDIR)/transactions /tmp/xs_crashme.vglog* /tmp/trace
	export $(TESTENV); ./xs_crashme 5000 $(RANDSEED) 2>/dev/null
	if [ -n "`cat /tmp/xs_crashme.vglog*`" ]; then echo Valgrind complained; cat /tmp/xs_crashme.vglog*; exit 1; fi
	rm -rf $(TESTDIR)/store $(TESTDIR)/transactions /tmp/xs_crashme.vglog* /tmp/trace

.PHONY: randomcheck-fast
randomcheck-fast: xs_random xenstored_test $(TESTDIR)
	@$(TESTENV) ./xs_random --fast /tmp/xs_random 2000 $(RANDSEED)

.PHONY: stresstest
stresstest: xs_stress xenstored_test $(TESTDIR)
	rm -rf $(TESTDIR)/store $(TESTDIR)/transactions
	export $(TESTENV); PID=`./xenstored_test --output-pid --trace-file=/tmp/trace`; ./xs_stress 5000; ret=$$?; kill $$PID; exit $$ret

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
	$(INSTALL_DIR) $(DESTDIR)/usr/bin
	$(INSTALL_DIR) $(DESTDIR)/usr/sbin
	$(INSTALL_DIR) $(DESTDIR)/usr/include
	$(INSTALL_PROG) xenstored $(DESTDIR)/usr/sbin
	$(INSTALL_PROG) $(CLIENTS) $(DESTDIR)/usr/bin
	$(INSTALL_PROG) xenstore-control $(DESTDIR)/usr/bin
	$(INSTALL_PROG) xenstore-ls $(DESTDIR)/usr/bin
	$(INSTALL_DIR) $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_PROG) libxenstore.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)
	ln -sf libxenstore.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)/libxenstore.so.$(MAJOR)
	ln -sf libxenstore.so.$(MAJOR) $(DESTDIR)/usr/$(LIBDIR)/libxenstore.so
	$(INSTALL_DATA) libxenstore.a $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DATA) xs.h $(DESTDIR)/usr/include
	$(INSTALL_DATA) xs_lib.h $(DESTDIR)/usr/include

-include $(PROG_DEP)

# never delete any intermediate files.
.SECONDARY:
