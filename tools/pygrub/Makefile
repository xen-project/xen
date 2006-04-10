
XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

all: build
build:
	CFLAGS="$(CFLAGS)" python setup.py build

ifndef XEN_PYTHON_NATIVE_INSTALL
install: all
	CFLAGS="$(CFLAGS)" python setup.py install --home="$(DESTDIR)/usr"
else
install: all
	CFLAGS="$(CFLAGS)" python setup.py install --root="$(DESTDIR)"
endif

clean:
	rm -rf build tmp *.pyc *.pyo *.o *.a *~ a.out
