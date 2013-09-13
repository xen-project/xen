XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror

CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_xeninclude)
CFLAGS += $(CFLAGS_libxenstore)

HDRS     = $(wildcard *.h)

TARGETS-y := xenperf xenpm xen-tmem-list-parse gtraceview gtracestat xenlockprof xenwatchdogd xencov
TARGETS-$(CONFIG_X86) += xen-detect xen-hvmctx xen-hvmcrash xen-lowmemd xen-mfndump
TARGETS-$(CONFIG_MIGRATE) += xen-hptool
TARGETS := $(TARGETS-y)

SUBDIRS := $(SUBDIRS-y)

INSTALL_BIN-y := xencons xencov_split
INSTALL_BIN-$(CONFIG_X86) += xen-detect
INSTALL_BIN := $(INSTALL_BIN-y)

INSTALL_SBIN-y := xen-bugtool xen-python-path xenperf xenpm xen-tmem-list-parse gtraceview \
	gtracestat xenlockprof xenwatchdogd xen-ringwatch xencov
INSTALL_SBIN-$(CONFIG_X86) += xen-hvmctx xen-hvmcrash xen-lowmemd xen-mfndump
INSTALL_SBIN-$(CONFIG_MIGRATE) += xen-hptool
INSTALL_SBIN := $(INSTALL_SBIN-y)

INSTALL_PRIVBIN-y := xenpvnetboot
INSTALL_PRIVBIN := $(INSTALL_PRIVBIN-y)

# Include configure output (config.h) to headers search path
CFLAGS += -I$(XEN_ROOT)/tools

.PHONY: all
all: build

.PHONY: build
build: $(TARGETS)
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d; done

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(BINDIR)
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_DIR) $(DESTDIR)$(PRIVATE_BINDIR)
	$(INSTALL_PYTHON_PROG) $(INSTALL_BIN) $(DESTDIR)$(BINDIR)
	$(INSTALL_PYTHON_PROG) $(INSTALL_SBIN) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PYTHON_PROG) $(INSTALL_PRIVBIN) $(DESTDIR)$(PRIVATE_BINDIR)
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d install-recurse; done

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) *~ $(DEPS)
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d clean; done

xen-hvmctx: xen-hvmctx.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

xen-hvmcrash: xen-hvmcrash.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

xenperf: xenperf.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

xenpm: xenpm.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

gtracestat: gtracestat.o
	$(CC) $(LDFLAGS) -o $@ $< $(APPEND_LDFLAGS)

xenlockprof: xenlockprof.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

xen-hptool: xen-hptool.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore) $(APPEND_LDFLAGS)

xen-mfndump: xen-mfndump.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore) $(APPEND_LDFLAGS)

xenwatchdogd: xenwatchdogd.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

xen-lowmemd: xen-lowmemd.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(LDLIBS_libxenstore) $(APPEND_LDFLAGS)

gtraceview: gtraceview.o
	$(CC) $(LDFLAGS) -o $@ $< $(CURSES_LIBS) $(APPEND_LDFLAGS)

xencov: xencov.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

-include $(DEPS)
