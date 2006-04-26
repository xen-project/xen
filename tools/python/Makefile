XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: build

.PHONY: build
build:
	CFLAGS="$(CFLAGS)" python setup.py build

.PHONY: install
ifndef XEN_PYTHON_NATIVE_INSTALL
install: all
	CFLAGS="$(CFLAGS)" python setup.py install --home="$(DESTDIR)/usr" --prefix="" --force
else
install: all
	CFLAGS="$(CFLAGS)" python setup.py install --root="$(DESTDIR)" --force
endif

.PHONY: test
test:
	export LD_LIBRARY_PATH=$$(readlink -f ../libxc):$$(readlink -f ../xenstore); python test.py -b -u

.PHONY: clean
clean:
	rm -rf build *.pyc *.pyo *.o *.a *~
