XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror

CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_xeninclude)
CFLAGS += $(CFLAGS_libxenstore)

HDRS     = $(wildcard *.h)

TARGETS-y := xenperf xenpm xen-tmem-list-parse gtraceview gtracestat xenlockprof xenwatchdogd
TARGETS-$(CONFIG_X86) += xen-detect xen-hvmctx xen-hvmcrash xen-lowmemd
TARGETS-$(CONFIG_MIGRATE) += xen-hptool
TARGETS := $(TARGETS-y)

SUBDIRS-$(CONFIG_LOMOUNT) += lomount
SUBDIRS-$(CONFIG_MINITERM) += miniterm
SUBDIRS := $(SUBDIRS-y)

INSTALL_BIN-y := xencons
INSTALL_BIN-$(CONFIG_X86) += xen-detect
INSTALL_BIN := $(INSTALL_BIN-y)

INSTALL_SBIN-y := xm xen-bugtool xen-python-path xend xenperf xsview xenpm xen-tmem-list-parse gtraceview gtracestat xenlockprof xenwatchdogd xen-ringwatch xen-lowmemd
INSTALL_SBIN-$(CONFIG_X86) += xen-hvmctx xen-hvmcrash
INSTALL_SBIN-$(CONFIG_MIGRATE) += xen-hptool
INSTALL_SBIN := $(INSTALL_SBIN-y)

.PHONY: all
all: build

.PHONY: build
build: $(TARGETS)
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d; done

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(BINDIR)
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PYTHON_PROG) $(INSTALL_BIN) $(DESTDIR)$(BINDIR)
	$(INSTALL_PYTHON_PROG) $(INSTALL_SBIN) $(DESTDIR)$(SBINDIR)
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

xenwatchdogd: xenwatchdogd.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

xen-lowmemd: xen-lowmemd.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(LDLIBS_libxenstore) $(APPEND_LDFLAGS)

gtraceview: gtraceview.o
	$(CC) $(LDFLAGS) -o $@ $< $(CURSES_LIBS) $(APPEND_LDFLAGS)

-include $(DEPS)
