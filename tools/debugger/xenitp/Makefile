XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

#CFLAGS  += -Werror -g -O0

CFLAGS  += $(CFLAGS_libxenctrl)

LIBBIN   = 

ifeq ($(XEN_TARGET_ARCH),ia64)
LIBBIN  += xenitp
endif

.PHONY: all
all: build

.PHONY: build
build: $(LIBBIN)

.PHONY: install
install: build
	[ -z "$(LIBBIN)" ] || $(INSTALL_DIR) $(DESTDIR)$(PRIVATE_BINDIR)
	[ -z "$(LIBBIN)" ] || $(INSTALL_PROG) $(LIBBIN) $(DESTDIR)$(PRIVATE_BINDIR)

.PHONY: clean
clean:
	$(RM) *.a *.so *.o *.rpm $(LIBBIN)

XENITP_OBJS=xenitp.o ia64-dis.o ia64-opc.o cpu-ia64-opc.o

xenitp: $(XENITP_OBJS)
	$(CC) $(CFLAGS) -o $@ $(XENITP_OBJS) $(LDLIBS_libxenctrl)
