
XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: build
.PHONY: build
build:
	CC="$(CC)" CFLAGS="$(CFLAGS)" python setup.py build

.PHONY: install
ifndef XEN_PYTHON_NATIVE_INSTALL
install: all
	CC="$(CC)" CFLAGS="$(CFLAGS)" python setup.py install --home="$(DESTDIR)/usr" --prefix=""
else
install: all
	CC="$(CC)" CFLAGS="$(CFLAGS)" python setup.py install --root="$(DESTDIR)"
endif

.PHONY: clean
clean:
	rm -rf build tmp *.pyc *.pyo *.o *.a *~ a.out
