XEN_ROOT = $(CURDIR)/../../..
include ./Rules.mk

SUBDIRS-y += gx
SUBDIRS-y += xg

TARGETS := gdbsx

.PHONY: all
all: $(TARGETS)

.PHONY: clean
clean: subdirs-clean
	rm -f $(TARGETS)

.PHONY: distclean
distclean: clean

.PHONY: install
install: all
	[ -d $(DESTDIR)$(sbindir) ] || $(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) gdbsx $(DESTDIR)$(sbindir)/gdbsx

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(sbindir)/gdbsx

gdbsx: gx/gx_all.a xg/xg_all.a 
	$(CC) $(LDFLAGS) -o $@ $^

xg/xg_all.a: FORCE
	$(MAKE) -C xg
gx/gx_all.a: FORCE
	$(MAKE) -C gx
