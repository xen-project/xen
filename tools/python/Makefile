XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: build

PY_CFLAGS = $(CFLAGS) $(PY_NOOPT_CFLAGS)
PY_LDFLAGS = $(SHLIB_LDFLAGS) $(APPEND_LDFLAGS)
INSTALL_LOG = build/installed_files.txt

setup.py = CC="$(CC)" CFLAGS="$(PY_CFLAGS)" LDSHARED="$(CC)" LDFLAGS="$(PY_LDFLAGS)" \
           SHLIB_libxenctrl="$(SHLIB_libxenctrl)" \
           SHLIB_libxenguest="$(SHLIB_libxenguest)" \
           SHLIB_libxenstore="$(SHLIB_libxenstore)" \
           $(PYTHON) setup.py

.PHONY: build
build:
	$(setup.py) build

.PHONY: install
install:
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(setup.py) install --record $(INSTALL_LOG) $(PYTHON_PREFIX_ARG) \
		--root="$(DESTDIR)" --force
	$(INSTALL_PYTHON_PROG) scripts/convert-legacy-stream $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PYTHON_PROG) scripts/verify-stream-v2 $(DESTDIR)$(LIBEXEC_BIN)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(LIBEXEC_BIN)/verify-stream-v2
	rm -f $(DESTDIR)$(LIBEXEC_BIN)/convert-legacy-stream
	if [ -e $(INSTALL_LOG) ]; then \
		cat $(INSTALL_LOG) | xargs -i rm -f $(DESTDIR)/{}; \
	fi

.PHONY: test
test:
	LD_LIBRARY_PATH=$$(readlink -f ../libs/ctrl):$$(readlink -f ../xenstore) $(PYTHON) -m unittest discover -v

.PHONY: clean
clean:
	find . \( -name "*.py[ocd]" -o -name "*~" -o -name "_*.[hc]" \) -delete
	rm -rf build/
	rm -f $(DEPS_RM)

.PHONY: distclean
distclean: clean

-include $(DEPS_INCLUDE)
