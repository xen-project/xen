
XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: build
.PHONY: build
build:
	CC="$(CC)" CFLAGS="$(CFLAGS)" python setup.py build

.PHONY: install
install: all
	CC="$(CC)" CFLAGS="$(CFLAGS)" python setup.py install \
		--prefix="$(PREFIX)" --root="$(DESTDIR)" --force
	$(INSTALL_DIR) $(DESTDIR)/var/run/xend/boot

.PHONY: clean
clean:
	rm -rf build tmp *.pyc *.pyo *.o *.a *~ a.out $(DEPS)

-include $(DEPS)
