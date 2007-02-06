XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: build

.PHONY: build
build:
	CC="$(CC)" CFLAGS="$(CFLAGS)" python setup.py build
	if which $(MSGFMT) >/dev/null ; then \
          for file in `cd ./xen/xm; find messages -name xen-xm.po`; do \
            dest=`echo "build/$$file" | \
                  sed -e 's#xen-xm.po#LC_MESSAGES/xen-xm.mo#'`; \
            mkdir -p `dirname "$$dest"`; \
            $(MSGFMT) -c -o "$$dest" "xen/xm/$$file"; \
          done; \
        fi

.PHONY: install
ifndef XEN_PYTHON_NATIVE_INSTALL
install: install-messages
	CC="$(CC)" CFLAGS="$(CFLAGS)" python setup.py install --home="$(DESTDIR)/usr" --prefix="" --force
else
install: install-messages
	CC="$(CC)" CFLAGS="$(CFLAGS)" python setup.py install --root="$(DESTDIR)" --force
endif

install-messages: all
	if which $(MSGFMT) >/dev/null ; then \
	  mkdir -p "$(DESTDIR)/usr/share/locale"; \
	  cp -R build/messages/* "$(DESTDIR)/usr/share/locale/"; \
	fi

.PHONY: test
test:
	export LD_LIBRARY_PATH=$$(readlink -f ../libxc):$$(readlink -f ../xenstore); python test.py -b -u

.PHONY: clean
clean:
	rm -rf build *.pyc *.pyo *.o *.a *~
