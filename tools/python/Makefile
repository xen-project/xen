XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all build install clean

all: build
build:
	CFLAGS="$(CFLAGS)" python setup.py build

ifndef XEN_PYTHON_NATIVE_INSTALL
install: all
	CFLAGS="$(CFLAGS)" python setup.py install --home="$(DESTDIR)/usr" --force
else
install: all
	CFLAGS="$(CFLAGS)" python setup.py install --root="$(DESTDIR)" --force
endif

test:
	export LD_LIBRARY_PATH=$$(readlink -f ../libxc):$$(readlink -f ../xenstore); python test.py -b -u

clean:
	rm -rf build *.pyc *.pyo *.o *.a *~
