
XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: build
.PHONY: build
build:
	CC="$(CC)" CFLAGS="$(CFLAGS)" python setup.py build

.PHONY: install
ifndef XEN_PYTHON_NATIVE_INSTALL
install: LIBPATH=$(shell PYTHONPATH=../python/xen/util python -c "import auxbin; print auxbin.libpath()")
install: all
	CC="$(CC)" CFLAGS="$(CFLAGS)" python setup.py install --home="$(DESTDIR)/usr" --prefix="" --install-lib="$(DESTDIR)$(LIBPATH)/python"
	$(INSTALL_DIR) -p $(DESTDIR)/var/run/xend/boot
else
install: all
	CC="$(CC)" CFLAGS="$(CFLAGS)" python setup.py install --root="$(DESTDIR)"
	$(INSTALL_DIR) -p $(DESTDIR)/var/run/xend/boot
endif

.PHONY: clean
clean:
	rm -rf build tmp *.pyc *.pyo *.o *.a *~ a.out
