
XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

all:
	CFLAGS="$(CFLAGS)" python setup.py build

install: all
	CFLAGS="$(CFLAGS)" python setup.py install --home="$(DESTDIR)/usr"

clean:
	rm -rf build *.pyc *.pyo *.o *.a *~
