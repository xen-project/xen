XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += $(CFLAGS_libxenctrl)

TARGETS := flask-loadpolicy flask-setenforce flask-getenforce flask-label-pci flask-get-bool flask-set-bool

.PHONY: all
all: $(TARGETS)

flask-loadpolicy: loadpolicy.o
	$(CC) $(LDFLAGS) $< $(LDLIBS) $(LDLIBS_libxenctrl) -o $@

flask-setenforce: setenforce.o
	$(CC) $(LDFLAGS) $< $(LDLIBS) $(LDLIBS_libxenctrl) -o $@

flask-getenforce: getenforce.o
	$(CC) $(LDFLAGS) $< $(LDLIBS) $(LDLIBS_libxenctrl) -o $@

flask-label-pci: label-pci.o
	$(CC) $(LDFLAGS) $< $(LDLIBS) $(LDLIBS_libxenctrl) -o $@

flask-get-bool: get-bool.o
	$(CC) $(LDFLAGS) $< $(LDLIBS) $(LDLIBS_libxenctrl) -o $@

flask-set-bool: set-bool.o
	$(CC) $(LDFLAGS) $< $(LDLIBS) $(LDLIBS_libxenctrl) -o $@

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) $(DEPS_RM)

.PHONY: distclean
distclean: clean

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) $(TARGETS) $(DESTDIR)$(sbindir)

.PHONY: uninstall
uninstall:
	rm -f $(addprefix $(DESTDIR)$(sbindir)/, $(TARGETS))

-include $(DEPS_INCLUDE)
