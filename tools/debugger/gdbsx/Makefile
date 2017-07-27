XEN_ROOT = $(CURDIR)/../../..
include ./Rules.mk

.PHONY: all
all:
	$(MAKE) -C gx
	$(MAKE) -C xg
	$(MAKE) gdbsx

.PHONY: clean
clean:
	rm -f xg_all.a gx_all.a gdbsx
	set -e; for d in xg gx; do $(MAKE) -C $$d clean; done

.PHONY: distclean
distclean: clean
	set -e; for d in xg gx; do $(MAKE) -c $$d distclean; done

.PHONY: install
install: all
	[ -d $(DESTDIR)$(sbindir) ] || $(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) gdbsx $(DESTDIR)$(sbindir)/gdbsx

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(sbindir)/gdbsx

gdbsx: gx/gx_all.a xg/xg_all.a 
	$(CC) -o $@ $^

xg/xg_all.a:
	$(MAKE) -C xg
gx/gx_all.a:
	$(MAKE) -C gx
