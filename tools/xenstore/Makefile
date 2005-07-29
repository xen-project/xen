XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk
LIBDIR = lib
XEN_LIBXC          = $(XEN_ROOT)/tools/libxc

INSTALL         = install
INSTALL_DATA	= $(INSTALL) -m0644
INSTALL_PROG    = $(INSTALL) -m0755
INSTALL_DIR     = $(INSTALL) -d -m0755

PROFILE=#-pg
BASECFLAGS=-Wall -W -g 
# Make gcc generate dependencies.
BASECFLAGS += -Wp,-MD,.$(@F).d
PROG_DEP = .*.d
#BASECFLAGS+= -O3 $(PROFILE)
#BASECFLAGS+= -I$(XEN_ROOT)/tools
BASECFLAGS+= -I$(XEN_ROOT)/tools/libxc
BASECFLAGS+= -I$(XEN_ROOT)/xen/include/public
BASECFLAGS+= -I.

CFLAGS  += $(BASECFLAGS)
LDFLAGS += $(PROFILE) -L$(XEN_LIBXC)
TESTDIR  = `pwd`/testsuite/tmp
TESTFLAGS= -DTESTING
TESTENV  = XENSTORED_ROOTDIR=$(TESTDIR) XENSTORED_RUNDIR=$(TESTDIR)

all: xen xenstored libxenstore.a libxenstore-pic.a

testcode: xen xs_test xenstored_test xs_random xs_dom0_test

xen:
	ln -sf $(XEN_ROOT)/xen/include/public $@

xenstored: xenstored_core.o xenstored_watch.o xenstored_domain.o xenstored_transaction.o xs_lib.o talloc.o utils.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -lxc -o $@

xenstored_test: xenstored_core_test.o xenstored_watch_test.o xenstored_domain_test.o xenstored_transaction_test.o xs_lib.o talloc_test.o fake_libxc.o utils.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

xs_test: xs_test.o xs_lib.o utils.o
xs_random: xs_random.o xs_test_lib.o xs_lib.o talloc.o utils.o
xs_stress: xs_stress.o xs_test_lib.o xs_lib.o talloc.o utils.o
xs_watch_stress: xs_watch_stress.o xs_test_lib.o xs_lib.o talloc.o utils.o

xs_test.o xs_stress.o xs_watch_stress.o xenstored_core_test.o xenstored_watch_test.o xenstored_transaction_test.o xenstored_domain_test.o xs_random.o xs_test_lib.o talloc_test.o fake_libxc.o: CFLAGS=$(BASECFLAGS) $(TESTFLAGS)

xenstored_%_test.o: xenstored_%.c
	$(COMPILE.c) -o $@ $<

xs_test_lib.o: xs.c
	$(COMPILE.c) -o $@ $<

talloc_test.o: talloc.c
	$(COMPILE.c) -o $@ $<

LIB_OBJS     := xs.o xs_lib.o

LIB_OBJS_A   := $(patsubst %.o,libxenstore.a(%.o),$(LIB_OBJS))
LIB_OBJS_PIC := $(patsubst %.o,libxenstore-pic.a(%.opic),$(LIB_OBJS))

libxenstore.a: $(LIB_OBJS_A)

libxenstore-pic.a: $(LIB_OBJS_PIC)

clean: testsuite-clean
	rm -f *.o *.opic *.a
	rm -f xen xenstored xs_random xs_stress xs_watch_stress
	rm -f xs_test xenstored_test xs_dom0_test
	-$(RM) $(PROG_DEP)

check: testsuite-run randomcheck stresstest

testsuite-run: xen xenstored_test xs_test
	$(TESTENV) testsuite/test.sh

testsuite-clean:
	rm -rf $(TESTDIR)

# Make this visible so they can see repeat tests without --fast if they
# fail.
RANDSEED=$(shell date +%s)
randomcheck: xs_random xenstored_test
	$(TESTENV) ./xs_random --simple --fast /tmp/xs_random 200000 $(RANDSEED)
	$(TESTENV) ./xs_random --fast /tmp/xs_random 100000 $(RANDSEED)
	$(TESTENV) ./xs_random --fail /tmp/xs_random 10000 $(RANDSEED)

stresstest: xs_stress xs_watch_stress xenstored_test
	rm -rf $(TESTDIR)/store $(TESTDIR)/transactions
	export $(TESTENV); PID=`./xenstored_test --output-pid --trace-file=/tmp/trace`; ./xs_stress 5000; ret=$$?; kill $$PID; exit $$ret
	rm -rf $(TESTDIR)/store $(TESTDIR)/transactions
	export $(TESTENV); PID=`./xenstored_test --output-pid`; ./xs_watch_stress; ret=$$?; kill $$PID; exit $$ret

xs_dom0_test: xs_dom0_test.o utils.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -lxc -o $@

TAGS:
	etags `find . -name '*.[ch]'`

tarball: clean
	cd .. && tar -c -j -v -h -f xenstore.tar.bz2 xenstore/

install: xenstored libxenstore.a libxenstore-pic.a
	$(INSTALL_DIR) -p $(DESTDIR)/var/run/xenstored
	$(INSTALL_DIR) -p $(DESTDIR)/var/lib/xenstored
	$(INSTALL_DIR) -p $(DESTDIR)/usr/sbin
	$(INSTALL_DIR) -p $(DESTDIR)/usr/include
	$(INSTALL_PROG) xenstored $(DESTDIR)/usr/sbin
	$(INSTALL_DIR) -p $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DATA) libxenstore.a $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DATA) libxenstore-pic.a $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DATA) xs.h $(DESTDIR)/usr/include
	$(INSTALL_DATA) xs_lib.h $(DESTDIR)/usr/include

-include $(PROG_DEP)

# never delete any intermediate files.
.SECONDARY:
