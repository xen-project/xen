XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: build

PY_CFLAGS = $(CFLAGS) $(PY_NOOPT_CFLAGS)
PY_LDFLAGS = $(LDFLAGS) $(APPEND_LDFLAGS)
INSTALL_LOG = build/installed_files.txt

.PHONY: build
build:
	CC="$(CC)" CFLAGS="$(PY_CFLAGS)" $(PYTHON) setup.py build

.PHONY: install
install:
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)

	CC="$(CC)" CFLAGS="$(PY_CFLAGS)" LDFLAGS="$(PY_LDFLAGS)" $(PYTHON) \
		setup.py install --record $(INSTALL_LOG) $(PYTHON_PREFIX_ARG) \
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
	LD_LIBRARY_PATH=$$(readlink -f ../libxc):$$(readlink -f ../xenstore) $(PYTHON) -m unittest discover

.PHONY: clean
clean:
	find . \( -name "*.py[ocd]" -o -name "*~" -o -name "_*.[hc]" \) -delete
	rm -rf build/
	rm -f $(DEPS_RM)

.PHONY: distclean
distclean: clean

-include $(DEPS_INCLUDE)
