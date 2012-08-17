XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: build

XENPATH = "xen/util/path.py"

genpath-target = $(call buildmakevars2file,$(XENPATH))
$(eval $(genpath-target))

.PHONY: build
build: genpath genwrap.py $(XEN_ROOT)/tools/libxl/libxl_types.idl \
		$(XEN_ROOT)/tools/libxl/idl.py
	PYTHONPATH=$(XEN_ROOT)/tools/libxl $(PYTHON) genwrap.py \
		$(XEN_ROOT)/tools/libxl/libxl_types.idl \
		xen/lowlevel/xl/_pyxl_types.h \
		xen/lowlevel/xl/_pyxl_types.c
	CC="$(CC)" CFLAGS="$(CFLAGS)" $(PYTHON) setup.py build

.PHONY: install
install: install-dtd
	CC="$(CC)" CFLAGS="$(CFLAGS)" $(PYTHON) setup.py install \
		$(PYTHON_PREFIX_ARG) --root="$(DESTDIR)" --force

install-dtd: all
	$(INSTALL_DIR) $(DESTDIR)$(SHAREDIR)/xen
	$(INSTALL_DATA) xen/xm/create.dtd $(DESTDIR)$(SHAREDIR)/xen

.PHONY: test
test:
	export LD_LIBRARY_PATH=$$(readlink -f ../libxc):$$(readlink -f ../xenstore); $(PYTHON) test.py -b -u

.PHONY: clean
clean:
	rm -f $(XENPATH)
	rm -rf build/ *.pyc *.pyo *.o *.a *~ xen/util/auxbin.pyc
	rm -f xen/lowlevel/xl/_pyxl_types.h
	rm -f xen/lowlevel/xl/_pyxl_types.c
	rm -f $(DEPS)

-include $(DEPS)
