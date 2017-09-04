
XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

PY_CFLAGS = $(CFLAGS) $(PY_NOOPT_CFLAGS)
PY_LDFLAGS = $(LDFLAGS) $(APPEND_LDFLAGS)
INSTALL_LOG = build/installed_files.txt

.PHONY: all
all: build
.PHONY: build
build:
	CC="$(CC)" CFLAGS="$(PY_CFLAGS)" $(PYTHON) setup.py build

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)/$(bindir)
	CC="$(CC)" CFLAGS="$(PY_CFLAGS)" LDFLAGS="$(PY_LDFLAGS)" $(PYTHON) \
		setup.py install --record $(INSTALL_LOG) $(PYTHON_PREFIX_ARG) \
		 --root="$(DESTDIR)" --install-scripts=$(LIBEXEC_BIN) --force
	set -e; if [ $(bindir) != $(LIBEXEC_BIN) -a \
	             "`readlink -f $(DESTDIR)/$(bindir)`" != \
	             "`readlink -f $(LIBEXEC_BIN)`" ]; then \
	    ln -sf $(LIBEXEC_BIN)/pygrub $(DESTDIR)/$(bindir); \
	fi

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)/$(bindir)/pygrub
	if [ -e $(INSTALL_LOG) ]; then \
		cat $(INSTALL_LOG) | xargs -i rm -f $(DESTDIR)/{}; \
	fi

.PHONY: clean
clean:
	rm -rf build tmp *.pyc *.pyo *.o *.a *~ a.out $(INSTALL_LOG) $(DEPS_RM)

.PHONY: distclean
distclean: clean

-include $(DEPS_INCLUDE)
