
XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

PY_CFLAGS = $(CFLAGS) $(PY_NOOPT_CFLAGS)
PY_LDFLAGS = $(SHLIB_LDFLAGS) $(APPEND_LDFLAGS)
INSTALL_LOG = build/installed_files.txt

setup.py = CC="$(CC)" CFLAGS="$(PY_CFLAGS)" LDSHARED="$(CC)" LDFLAGS="$(PY_LDFLAGS)" \
           $(PYTHON) setup.py

.PHONY: all
all: build
.PHONY: build
build:
	$(setup.py) build

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)/$(bindir)
	$(INSTALL_DIR) $(DESTDIR)/$(LIBEXEC_BIN)
	$(setup.py) install --record $(INSTALL_LOG) $(PYTHON_PREFIX_ARG) \
		--root="$(DESTDIR)" --force
	$(INSTALL_PYTHON_PROG) src/pygrub $(DESTDIR)/$(LIBEXEC_BIN)/pygrub

.PHONY: uninstall
uninstall:
	if [ -e $(INSTALL_LOG) ]; then \
		cat $(INSTALL_LOG) | xargs -i rm -f $(DESTDIR)/{}; \
	fi

.PHONY: clean
clean:
	rm -rf build tmp *.pyc *.pyo *.o *.a *~ a.out $(INSTALL_LOG) $(DEPS_RM)

.PHONY: distclean
distclean: clean

-include $(DEPS_INCLUDE)
