XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk

#CFLAGS  += -Werror -g -O0

CFLAGS  += $(CFLAGS_libxenctrl)

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

BIN      =
LIBBIN   = 
SCRIPTS  =
MAN1     = $(wildcard *.1)
MAN8     = $(wildcard *.8)

ifeq ($(XEN_TARGET_ARCH),ia64)
LIBBIN  += xenitp
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
	if [ "x$(SCRIPTS)" != "x" ]; then \
		$(INSTALL_PROG) $(BIN) $(SCRIPTS) $(DESTDIR)$(BINDIR); \
	fi
	[ -z "$(LIBBIN)" ] || $(INSTALL_PROG) $(LIBBIN) $(DESTDIR)$(PRIVATE_BINDIR)
	if [ "x$(MAN1)" != "x" ]; then \
		$(INSTALL_DATA) $(MAN1) $(DESTDIR)$(MAN1DIR); \
	fi
	if [ "x$(MAN1)" != "x" ]; then \
		$(INSTALL_DATA) $(MAN8) $(DESTDIR)$(MAN8DIR); \
	fi

.PHONY: clean
clean:
	$(RM) *.a *.so *.o *.rpm $(BIN) $(LIBBIN)

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS_libxenctrl)

XENITP_OBJS=xenitp.o ia64-dis.o ia64-opc.o cpu-ia64-opc.o
xenitp: $(XENITP_OBJS)
	$(CC) $(CFLAGS) -o $@ $(XENITP_OBJS) $(LDLIBS_libxenctrl)
