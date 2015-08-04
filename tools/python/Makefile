XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: build

PY_CFLAGS = $(CFLAGS) $(PY_NOOPT_CFLAGS) $(LDFLAGS) $(APPEND_LDFLAGS)

.PHONY: build
build: genwrap.py $(XEN_ROOT)/tools/libxl/libxl_types.idl \
		$(XEN_ROOT)/tools/libxl/idl.py
	PYTHONPATH=$(XEN_ROOT)/tools/libxl $(PYTHON) genwrap.py \
		$(XEN_ROOT)/tools/libxl/libxl_types.idl \
		xen/lowlevel/xl/_pyxl_types.h \
		xen/lowlevel/xl/_pyxl_types.c
	CC="$(CC)" CFLAGS="$(PY_CFLAGS)" $(PYTHON) setup.py build

.PHONY: install
install:
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)

	CC="$(CC)" CFLAGS="$(PY_CFLAGS)" $(PYTHON) setup.py install \
		$(PYTHON_PREFIX_ARG) --root="$(DESTDIR)" --force

	$(INSTALL_PROG) scripts/convert-legacy-stream $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) scripts/verify-stream-v2 $(DESTDIR)$(LIBEXEC_BIN)

.PHONY: test
test:
	export LD_LIBRARY_PATH=$$(readlink -f ../libxc):$$(readlink -f ../xenstore); $(PYTHON) test.py -b -u

.PHONY: clean
clean:
	find . \( -name "*.py[ocd]" -o -name "*~" -o -name "_*.[hc]" \) -delete
	rm -rf build/
	rm -f $(DEPS)

.PHONY: distclean
distclean: clean

-include $(DEPS)
