XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk
XEN_LIBXC          = $(XEN_ROOT)/tools/libxc

INSTALL         = install
INSTALL_DATA	= $(INSTALL) -m0644
INSTALL_PROG    = $(INSTALL) -m0755
INSTALL_DIR     = $(INSTALL) -d -m0755

PROFILE=#-pg
BASECFLAGS=-Wall -g -Werror
# Make gcc generate dependencies.
BASECFLAGS += -Wp,-MD,.$(@F).d
PROG_DEP = .*.d
BASECFLAGS+= -O3 $(PROFILE)
#BASECFLAGS+= -I$(XEN_ROOT)/tools
BASECFLAGS+= -I$(XEN_ROOT)/tools/libxc
BASECFLAGS+= -I.

CFLAGS  += $(BASECFLAGS)
LDFLAGS += $(PROFILE) -L$(XEN_LIBXC)
TESTDIR  = testsuite/tmp
TESTFLAGS= -DTESTING
TESTENV  = XENSTORED_ROOTDIR=$(TESTDIR) XENSTORED_RUNDIR=$(TESTDIR)

CLIENTS := xenstore-exists xenstore-list xenstore-read xenstore-rm
CLIENTS += xenstore-write
CLIENTS_OBJS := $(patsubst xenstore-%,xenstore_%.o,$(CLIENTS))

all: libxenstore.so xenstored $(CLIENTS) xs_tdb_dump xsls

testcode: xs_test xenstored_test xs_random

xenstored: xenstored_core.o xenstored_watch.o xenstored_domain.o xenstored_transaction.o xs_lib.o talloc.o utils.o tdb.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -lxenctrl -o $@

$(CLIENTS): xenstore-%: xenstore_%.o libxenstore.so
	$(LINK.o) $< $(LOADLIBES) $(LDLIBS) -lxenctrl -L. -lxenstore -o $@

$(CLIENTS_OBJS): xenstore_%.o: xenstore_client.c
	$(COMPILE.c) -DCLIENT_$(*F) -o $@ $<

xsls: xsls.o libxenstore.so
	$(LINK.o) $< $(LOADLIBES) $(LDLIBS) -lxenctrl -L. -lxenstore -o $@

xenstored_test: xenstored_core_test.o xenstored_watch_test.o xenstored_domain_test.o xenstored_transaction_test.o xs_lib.o talloc_test.o fake_libxc.o utils.o tdb.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

xs_tdb_dump: xs_tdb_dump.o utils.o tdb.o talloc.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

xs_test xs_random xs_stress xs_crashme: LDFLAGS+=-lpthread
xs_test: xs_test.o xs_lib.o utils.o
xs_random: xs_random.o xs_test_lib.o xs_lib.o talloc.o utils.o
xs_stress: xs_stress.o xs_test_lib.o xs_lib.o talloc.o utils.o
xs_crashme: xs_crashme.o xs_lib.o talloc.o utils.o

speedtest: speedtest.o xs.o xs_lib.o utils.o talloc.o

check-speed: speedtest xenstored_test $(TESTDIR)
	$(TESTENV) time ./speedtest 100

xs_test.o xs_stress.o xenstored_core_test.o xenstored_watch_test.o xenstored_transaction_test.o xenstored_domain_test.o xs_random.o xs_test_lib.o talloc_test.o fake_libxc.o xs_crashme.o: CFLAGS=$(BASECFLAGS) $(TESTFLAGS)

xenstored_%_test.o: xenstored_%.c
	$(COMPILE.c) -o $@ $<

xs_test_lib.o: xs.c
	$(COMPILE.c) -o $@ $<

talloc_test.o: talloc.c
	$(COMPILE.c) -o $@ $<

libxenstore.so: xs.opic xs_lib.opic
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname -Wl,libxenstore.so -shared -o $@ $^ -lpthread

clean: testsuite-clean
	rm -f *.o *.opic *.so
	rm -f xenstored xs_random xs_stress xs_crashme
	rm -f xs_test xenstored_test xs_tdb_dump
	$(RM) $(PROG_DEP)

print-dir:
	@echo -n tools/xenstore: 

print-end:
	@echo

check: print-dir testsuite-fast randomcheck-fast print-end

fullcheck: testsuite-run randomcheck stresstest

$(TESTDIR):
	mkdir $@

testsuite-run: xenstored_test xs_test $(TESTDIR)
	$(TESTENV) testsuite/test.sh && echo

testsuite-fast: xenstored_test xs_test $(TESTDIR)
	@$(TESTENV) testsuite/test.sh --fast

testsuite-clean:
	rm -rf $(TESTDIR)

# Make this visible so they can see repeat tests without --fast if they
# fail.
RANDSEED=$(shell date +%s)
randomcheck: xs_random xenstored_test $(TESTDIR)
	$(TESTENV) ./xs_random --simple --fast /tmp/xs_random 200000 $(RANDSEED) && echo
	$(TESTENV) ./xs_random --fast /tmp/xs_random 100000 $(RANDSEED) && echo
#	$(TESTENV) ./xs_random --fail /tmp/xs_random 10000 $(RANDSEED)

crashme:  xs_crashme xenstored_test $(TESTDIR)
	rm -rf $(TESTDIR)/store $(TESTDIR)/transactions /tmp/xs_crashme.vglog* /tmp/trace
	export $(TESTENV); ./xs_crashme 5000 $(RANDSEED) 2>/dev/null
	if [ -n "`cat /tmp/xs_crashme.vglog*`" ]; then echo Valgrind complained; cat /tmp/xs_crashme.vglog*; exit 1; fi
	rm -rf $(TESTDIR)/store $(TESTDIR)/transactions /tmp/xs_crashme.vglog* /tmp/trace

randomcheck-fast: xs_random xenstored_test $(TESTDIR)
	@$(TESTENV) ./xs_random --fast /tmp/xs_random 2000 $(RANDSEED)

stresstest: xs_stress xenstored_test $(TESTDIR)
	rm -rf $(TESTDIR)/store $(TESTDIR)/transactions
	export $(TESTENV); PID=`./xenstored_test --output-pid --trace-file=/tmp/trace`; ./xs_stress 5000; ret=$$?; kill $$PID; exit $$ret

TAGS:
	etags `find . -name '*.[ch]'`

tarball: clean
	cd .. && tar -c -j -v -h -f xenstore.tar.bz2 xenstore/

install: libxenstore.so xenstored xsls $(CLIENTS)
	$(INSTALL_DIR) -p $(DESTDIR)/var/run/xenstored
	$(INSTALL_DIR) -p $(DESTDIR)/var/lib/xenstored
	$(INSTALL_DIR) -p $(DESTDIR)/usr/bin
	$(INSTALL_DIR) -p $(DESTDIR)/usr/sbin
	$(INSTALL_DIR) -p $(DESTDIR)/usr/include
	$(INSTALL_PROG) xenstored $(DESTDIR)/usr/sbin
	$(INSTALL_PROG) $(CLIENTS) $(DESTDIR)/usr/bin
	$(INSTALL_PROG) xsls $(DESTDIR)/usr/bin
	$(INSTALL_DIR) -p $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DATA) libxenstore.so $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DATA) xs.h $(DESTDIR)/usr/include
	$(INSTALL_DATA) xs_lib.h $(DESTDIR)/usr/include

-include $(PROG_DEP)

# never delete any intermediate files.
.SECONDARY:
