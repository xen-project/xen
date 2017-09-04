XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror
# Include configure output (config.h)
CFLAGS += -include $(XEN_ROOT)/tools/config.h
CFLAGS += $(CFLAGS_libxenevtchn)
CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_xeninclude)
CFLAGS += $(CFLAGS_libxenstore)

# Everything to be installed in regular bin/
INSTALL_BIN-$(CONFIG_X86)      += xen-cpuid
INSTALL_BIN-$(CONFIG_X86)      += xen-detect
INSTALL_BIN                    += xencons
INSTALL_BIN                    += xencov_split
INSTALL_BIN += $(INSTALL_BIN-y)

# Everything to be installed in regular sbin/
INSTALL_SBIN                   += xen-bugtool
INSTALL_SBIN-$(CONFIG_MIGRATE) += xen-hptool
INSTALL_SBIN-$(CONFIG_X86)     += xen-hvmcrash
INSTALL_SBIN-$(CONFIG_X86)     += xen-hvmctx
INSTALL_SBIN-$(CONFIG_X86)     += xen-lowmemd
INSTALL_SBIN-$(CONFIG_X86)     += xen-mfndump
INSTALL_SBIN                   += xen-ringwatch
INSTALL_SBIN                   += xen-tmem-list-parse
INSTALL_SBIN                   += xencov
INSTALL_SBIN                   += xenlockprof
INSTALL_SBIN                   += xenperf
INSTALL_SBIN                   += xenpm
INSTALL_SBIN                   += xenwatchdogd
INSTALL_SBIN                   += xen-livepatch
INSTALL_SBIN                   += xen-diag
INSTALL_SBIN += $(INSTALL_SBIN-y)

# Everything to be installed in a private bin/
INSTALL_PRIVBIN                += xenpvnetboot

# Everything to be installed
TARGETS_ALL := $(INSTALL_BIN) $(INSTALL_SBIN) $(INSTALL_PRIVBIN)

# Everything which only needs copying to install
TARGETS_COPY += xen-bugtool
TARGETS_COPY += xen-ringwatch
TARGETS_COPY += xencons
TARGETS_COPY += xencov_split
TARGETS_COPY += xenpvnetboot

# Everything which needs to be built
TARGETS_BUILD := $(filter-out $(TARGETS_COPY),$(TARGETS_ALL))

.PHONY: all build
all build: $(TARGETS_BUILD)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(bindir)
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PYTHON_PROG) $(INSTALL_BIN) $(DESTDIR)$(bindir)
	$(INSTALL_PYTHON_PROG) $(INSTALL_SBIN) $(DESTDIR)$(sbindir)
	$(INSTALL_PYTHON_PROG) $(INSTALL_PRIVBIN) $(DESTDIR)$(LIBEXEC_BIN)

.PHONY: uninstall
uninstall:
	rm -f $(addprefix $(DESTDIR)$(LIBEXEC_BIN)/, $(INSTALL_PRIVBIN))
	rm -f $(addprefix $(DESTDIR)$(sbindir)/, $(INSTALL_SBIN))
	rm -f $(addprefix $(DESTDIR)$(bindir)/, $(INSTALL_BIN))

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS_BUILD) *~ $(DEPS_RM)

.PHONY: distclean
distclean: clean

xen-cpuid: xen-cpuid.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(APPEND_LDFLAGS)

xen-hvmctx: xen-hvmctx.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

xen-hvmcrash: xen-hvmcrash.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

xenperf: xenperf.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

xenpm: xenpm.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

xenlockprof: xenlockprof.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

# xen-hptool incorrectly uses libxc internals
xen-hptool.o: CFLAGS += -I$(XEN_ROOT)/tools/libxc $(CFLAGS_libxencall)
xen-hptool: xen-hptool.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenevtchn) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore) $(APPEND_LDFLAGS)

# xen-mfndump incorrectly uses libxc internals
xen-mfndump.o: CFLAGS += -I$(XEN_ROOT)/tools/libxc $(CFLAGS_libxencall)
xen-mfndump: xen-mfndump.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenevtchn) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(APPEND_LDFLAGS)

xenwatchdogd: xenwatchdogd.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

xen-livepatch: xen-livepatch.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

xen-diag: xen-diag.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

xen-lowmemd: xen-lowmemd.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenevtchn) $(LDLIBS_libxenctrl) $(LDLIBS_libxenstore) $(APPEND_LDFLAGS)

xencov: xencov.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

-include $(DEPS_INCLUDE)
