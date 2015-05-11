
XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

PY_CFLAGS = $(CFLAGS) $(PY_NOOPT_CFLAGS) $(APPEND_LDFLAGS)

.PHONY: all
all: build
.PHONY: build
build:
	CC="$(CC)" CFLAGS="$(PY_CFLAGS)" $(PYTHON) setup.py build

.PHONY: install
install: all
	CC="$(CC)" CFLAGS="$(PY_CFLAGS)" $(PYTHON) setup.py install \
		$(PYTHON_PREFIX_ARG) --root="$(DESTDIR)" \
		--install-scripts=$(LIBEXEC_BIN) --force
	set -e; if [ $(bindir) != $(LIBEXEC_BIN) -a \
	             "`readlink -f $(DESTDIR)/$(bindir)`" != \
	             "`readlink -f $(LIBEXEC_BIN)`" ]; then \
	    ln -sf $(LIBEXEC_BIN)/pygrub $(DESTDIR)/$(bindir); \
	fi

.PHONY: clean
clean:
	rm -rf build tmp *.pyc *.pyo *.o *.a *~ a.out $(DEPS)

.PHONY: distclean
distclean: clean

-include $(DEPS)
