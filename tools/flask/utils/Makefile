XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror
CFLAGS += $(CFLAGS_libxenctrl)

CLIENTS := flask-loadpolicy flask-setenforce flask-getenforce flask-label-pci flask-get-bool flask-set-bool

.PHONY: all
all: $(CLIENTS)

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
	$(RM) *.o $(CLIENTS) $(DEPS_RM)

.PHONY: distclean
distclean: clean

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) $(CLIENTS) $(DESTDIR)$(sbindir)

.PHONY: uninstall
uninstall:
	rm -f $(addprefix $(DESTDIR)$(sbindir)/, $(CLIENTS))

-include $(DEPS_INCLUDE)
