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

SUBDIRS-$(CONFIG_LOMOUNT) += lomount
SUBDIRS-$(CONFIG_MINITERM) += miniterm
SUBDIRS := $(SUBDIRS-y)

INSTALL_BIN  = $(TARGETS) xencons
INSTALL_SBIN = netfix xm xen-bugtool xen-python-path xend xenperf xsview

.PHONY: all
all: build

.PHONY: build
build: $(TARGETS)
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d; done

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(BINDIR)
	[ -d $(DESTDIR)/usr/sbin ] || $(INSTALL_DIR) $(DESTDIR)/usr/sbin
	$(INSTALL_PROG) $(INSTALL_BIN) $(DESTDIR)$(BINDIR)
	$(INSTALL_PROG) $(INSTALL_SBIN) $(DESTDIR)/usr/sbin
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d install-recurse; done

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) *~
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d clean; done

%.o: %.c $(HDRS) Makefile
	$(CC) -c $(CFLAGS) -o $@ $<

xenperf: %: %.o Makefile
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -L$(XEN_LIBXC) -lxenctrl
