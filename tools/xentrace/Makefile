XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror

CFLAGS += $(CFLAGS_libxenevtchn)
CFLAGS += $(CFLAGS_libxenctrl)
LDLIBS += $(LDLIBS_libxenevtchn)
LDLIBS += $(LDLIBS_libxenctrl)
LDLIBS += $(ARGP_LDFLAGS)

BIN-$(CONFIG_X86) = xenalyze
BIN      = $(BIN-y)
SBIN     = xentrace xentrace_setsize
LIBBIN   = xenctx
SCRIPTS  = xentrace_format

.PHONY: all
all: build

.PHONY: build
build: $(BIN) $(SBIN) $(LIBBIN)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(bindir)
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	[ -z "$(LIBBIN)" ] || $(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
ifneq ($(BIN),)
	$(INSTALL_PROG) $(BIN) $(DESTDIR)$(bindir)
endif
	$(INSTALL_PROG) $(SBIN) $(DESTDIR)$(sbindir)
	$(INSTALL_PYTHON_PROG) $(SCRIPTS) $(DESTDIR)$(bindir)
	[ -z "$(LIBBIN)" ] || $(INSTALL_PROG) $(LIBBIN) $(DESTDIR)$(LIBEXEC_BIN)

.PHONY: uninstall
uninstall:
	rm -f $(addprefix $(DESTDIR)$(LIBEXEC_BIN)/, $(LIBBIN))
	rm -f $(addprefix $(DESTDIR)$(bindir)/, $(SCRIPTS))
	rm -f $(addprefix $(DESTDIR)$(sbindir)/, $(SBIN))
ifneq ($(BIN),)
	rm -f $(addprefix $(DESTDIR)$(bindir)/, $(BIN))
endif

.PHONY: clean
clean:
	$(RM) *.a *.so *.o *.rpm $(BIN) $(SBIN) $(LIBBIN) $(DEPS_RM)

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

