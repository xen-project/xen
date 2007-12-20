XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

XEN_SECURITY_MODULE = dummy
ifeq ($(FLASK_ENABLE),y)
XEN_SECURITY_MODULE = flask
endif
ifeq ($(ACM_SECURITY),y)
XEN_SECURITY_MODULE = acm
endif

.PHONY: all
all: build

# For each new supported translation, add its name here, eg 'fr_FR'
# to cause the .po file to be built & installed, eg
LINGUAS :=
POPACKAGE := xen-xm
PODIR := xen/xm/messages
POTFILE := $(PODIR)/xen-xm.pot
I18NSRCFILES = $(shell find xen/xm/ -name '*.py')
CATALOGS = $(patsubst %,xen/xm/messages/%.mo,$(LINGUAS))
NLSDIR = /usr/share/locale

.PHONY: build buildpy
buildpy: xsm.py
	CC="$(CC)" CFLAGS="$(CFLAGS)" XEN_SECURITY_MODULE="$(XEN_SECURITY_MODULE)" python setup.py build

build: buildpy refresh-pot refresh-po $(CATALOGS)

# NB we take care to only update the .pot file it strings have
# actually changed. This is complicated by the embedded date
# string, hence the sed black magic. This avoids the expensive
# re-generation of .po files on every single build
refresh-pot: $(I18NSRCFILES)
	xgettext --default-domain=$(POPACAKGE) \
		--keyword=N_ \
		--keyword=_ \
		-o $(POTFILE)-tmp \
		$(I18NSRCFILES)
	sed -f remove-potcdate.sed < $(POTFILE) > $(POTFILE)-1
	sed -f remove-potcdate.sed < $(POTFILE)-tmp > $(POTFILE)-2
	set -e; if cmp -s $(POTFILE)-1 $(POTFILE)-2; then \
		rm -f $(POTFILE)-tmp $(POTFILE)-1 $(POTFILE)-2; \
	else \
		mv $(POTFILE)-tmp $(POTFILE); \
                rm -f $(POTFILE)-1 $(POTFILE)-2; \
	fi

refresh-po: $(POTFILE)
	set -e; for l in $(LINGUAS); do \
		if $(MSGMERGE) $(PODIR)/$$l.po $(POTFILE) > $(PODIR)/$$l-tmp ; then \
			mv -f $(PODIR)/$$l-tmp $(PODIR)/$$l.po ; \
			echo "$(MSGMERGE) of $$l.po succeeded" ; \
		else \
			echo "$(MSGMERGE) of $$l.po failed" ; \
			rm -f $(PODIR)/$$l-tmp ; \
		fi \
	done

%.mo: %.po
	$(MSGFMT) -c -o $@ $<

xsm.py:
	@(set -e; \
	  echo "XEN_SECURITY_MODULE = \""$(XEN_SECURITY_MODULE)"\""; \
	  echo "from xsm_core import *"; \
	  echo ""; \
	  echo "import xen.util.xsm."$(XEN_SECURITY_MODULE)"."$(XEN_SECURITY_MODULE)" as xsm_module"; \
	  echo ""; \
	  echo "xsm_init(xsm_module)"; \
	  echo "from xen.util.xsm."$(XEN_SECURITY_MODULE)"."$(XEN_SECURITY_MODULE)" import *"; \
	  echo "del xsm_module"; \
	  echo "") >xen/util/xsm/$@

.PHONY: install
ifndef XEN_PYTHON_NATIVE_INSTALL
install: LIBPATH=$(shell PYTHONPATH=xen/util python -c "import auxbin; print auxbin.libpath()")
install: install-messages install-dtd
	CC="$(CC)" CFLAGS="$(CFLAGS)" python setup.py install --home="$(DESTDIR)/usr" --prefix="" --force --install-lib="$(DESTDIR)$(LIBPATH)/python"
else
install: install-messages install-dtd
	CC="$(CC)" CFLAGS="$(CFLAGS)" python setup.py install --root="$(DESTDIR)" --force
endif

install-dtd: all
	$(INSTALL_DIR) $(DESTDIR)/usr/share/xen
	$(INSTALL_DATA) xen/xm/create.dtd $(DESTDIR)/usr/share/xen

install-messages: all
	set -e; if which $(MSGFMT) >/dev/null ; then \
		mkdir -p $(DESTDIR)$(NLSDIR); \
		for l in $(LINGUAS); do \
			$(INSTALL_DIR) $(DESTDIR)$(NLSDIR)/$$l; \
			$(INSTALL_DIR) $(DESTDIR)$(NLSDIR)/$$l/LC_MESSAGES; \
			$(INSTALL_DATA) $(PODIR)/$$l.mo \
				$(DESTDIR)$(NLSDIR)/$$l/LC_MESSAGES/$(POPACKAGE).mo; \
		done ; \
	fi

.PHONY: test
test:
	export LD_LIBRARY_PATH=$$(readlink -f ../libxc):$$(readlink -f ../xenstore); python test.py -b -u

.PHONY: clean
clean:
	rm -rf build *.pyc *.pyo *.o *.a *~ $(CATALOGS) xen/util/xsm/xsm.py xen/util/auxbin.pyc
