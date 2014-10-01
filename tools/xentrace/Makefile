XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror

CFLAGS += $(CFLAGS_libxenctrl)
LDLIBS += $(LDLIBS_libxenctrl)

BIN      = xentrace xentrace_setsize
LIBBIN   = xenctx
SCRIPTS  = xentrace_format
MAN1     = $(wildcard *.1)
MAN8     = $(wildcard *.8)

.PHONY: all
all: build

.PHONY: build
build: $(BIN) $(LIBBIN)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(BINDIR)
	[ -z "$(LIBBIN)" ] || $(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_DIR) $(DESTDIR)$(MAN1DIR)
	$(INSTALL_DIR) $(DESTDIR)$(MAN8DIR)
	$(INSTALL_PROG) $(BIN) $(DESTDIR)$(BINDIR)
	$(INSTALL_PYTHON_PROG) $(SCRIPTS) $(DESTDIR)$(BINDIR)
	[ -z "$(LIBBIN)" ] || $(INSTALL_PROG) $(LIBBIN) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_DATA) $(MAN1) $(DESTDIR)$(MAN1DIR)
	$(INSTALL_DATA) $(MAN8) $(DESTDIR)$(MAN8DIR)

.PHONY: clean
clean:
	$(RM) *.a *.so *.o *.rpm $(BIN) $(LIBBIN) $(DEPS)

xentrace: xentrace.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS) $(APPEND_LDFLAGS)

xenctx: xenctx.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS) $(APPEND_LDFLAGS)

xentrace_setsize: setsize.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS) $(APPEND_LDFLAGS)

-include $(DEPS)

