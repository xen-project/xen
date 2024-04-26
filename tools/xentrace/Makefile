XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += $(CFLAGS_libxenevtchn)
CFLAGS += $(CFLAGS_libxenctrl)
LDLIBS += $(LDLIBS_libxenevtchn)
LDLIBS += $(LDLIBS_libxenctrl)
LDLIBS += $(ARGP_LDFLAGS)

BIN     := xenalyze
SBIN    := xentrace xentrace_setsize
LIBBIN  := xenctx

TARGETS := $(BIN) $(SBIN) $(LIBBIN)

.PHONY: all
all: $(TARGETS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(bindir)
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) $(BIN) $(DESTDIR)$(bindir)
	$(INSTALL_PROG) $(SBIN) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) $(LIBBIN) $(DESTDIR)$(LIBEXEC_BIN)

.PHONY: uninstall
uninstall:
	rm -f $(addprefix $(DESTDIR)$(LIBEXEC_BIN)/, $(LIBBIN))
	rm -f $(addprefix $(DESTDIR)$(sbindir)/, $(SBIN))
	rm -f $(addprefix $(DESTDIR)$(bindir)/, $(BIN))

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) $(DEPS_RM)

.PHONY: distclean
distclean: clean

xentrace: xentrace.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS) $(APPEND_LDFLAGS)

xenctx: xenctx.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS) $(APPEND_LDFLAGS)

xentrace_setsize: setsize.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS) $(APPEND_LDFLAGS)

xenalyze: xenalyze.o mread.o
	$(CC) $(LDFLAGS) -o $@ $^ $(ARGP_LDFLAGS) $(APPEND_LDFLAGS)

-include $(DEPS_INCLUDE)

