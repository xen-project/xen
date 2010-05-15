XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror

CFLAGS  += $(CFLAGS_libxenctrl)
LDFLAGS += $(LDFLAGS_libxenctrl)

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

BIN      = xentrace xentrace_setsize
LIBBIN   = 
SCRIPTS  = xentrace_format
MAN1     = $(wildcard *.1)
MAN8     = $(wildcard *.8)

ifeq ($(XEN_TARGET_ARCH),x86_32)
LIBBIN  += xenctx
endif

ifeq ($(XEN_TARGET_ARCH),x86_64)
LIBBIN  += xenctx
endif

ifeq ($(XEN_TARGET_ARCH),ia64)
LIBBIN  += xenctx
endif

.PHONY: all
all: build

.PHONY: build
build: $(BIN) $(LIBBIN)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(BINDIR)
	[ -z "$(LIBBIN)" ] || $(INSTALL_DIR) $(DESTDIR)$(PRIVATE_BINDIR)
	$(INSTALL_DIR) $(DESTDIR)$(MAN1DIR)
	$(INSTALL_DIR) $(DESTDIR)$(MAN8DIR)
	$(INSTALL_PROG) $(BIN) $(DESTDIR)$(BINDIR)
	$(INSTALL_PYTHON_PROG) $(SCRIPTS) $(DESTDIR)$(BINDIR)
	[ -z "$(LIBBIN)" ] || $(INSTALL_PROG) $(LIBBIN) $(DESTDIR)$(PRIVATE_BINDIR)
	$(INSTALL_DATA) $(MAN1) $(DESTDIR)$(MAN1DIR)
	$(INSTALL_DATA) $(MAN8) $(DESTDIR)$(MAN8DIR)

.PHONY: clean
clean:
	$(RM) *.a *.so *.o *.rpm $(BIN) $(LIBBIN) $(DEPS)

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
xentrace_%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

-include $(DEPS)

