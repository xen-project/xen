XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS   += -Werror

INCLUDES += -I $(XEN_XC)
INCLUDES += -I $(XEN_LIBXC)
CFLAGS   += $(INCLUDES)

HDRS     = $(wildcard *.h)

TARGETS-y := xenperf
TARGETS-$(CONFIG_X86) += xen-detect
TARGETS := $(TARGETS-y)

INSTALL_BIN  = $(TARGETS) xencons
INSTALL_SBIN = netfix xm xen-bugtool xen-python-path xend xenperf

.PHONY: all
all: build

.PHONY: build
build: $(TARGETS)
	$(MAKE) -C miniterm
	$(MAKE) -C lomount

.PHONY: install
install: build
	[ -d $(DESTDIR)/usr/bin ] || $(INSTALL_DIR) $(DESTDIR)/usr/bin
	[ -d $(DESTDIR)/usr/sbin ] || $(INSTALL_DIR) $(DESTDIR)/usr/sbin
	$(INSTALL_PROG) $(INSTALL_BIN) $(DESTDIR)/usr/bin
	$(INSTALL_PROG) $(INSTALL_SBIN) $(DESTDIR)/usr/sbin
	$(MAKE) -C lomount install
#       No sense in installing miniterm on the Xen box.
#	$(MAKE) -C miniterm install

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) *~
	$(MAKE) -C miniterm clean
	$(MAKE) -C lomount clean

%.o: %.c $(HDRS) Makefile
	$(CC) -c $(CFLAGS) -o $@ $<

xenperf: %: %.o Makefile
	$(CC) $(CFLAGS) -o $@ $< -L$(XEN_LIBXC) -lxenctrl
