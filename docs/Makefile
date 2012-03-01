#!/usr/bin/make -f

XEN_ROOT=$(CURDIR)/..
include $(XEN_ROOT)/Config.mk
include $(XEN_ROOT)/docs/Docs.mk

VERSION		= xen-unstable

DOC_MAN5SRC	:= $(wildcard man/*.pod.5)
DOC_MAN1SRC	:= $(wildcard man/*.pod.1)
DOC_MAN1	:= $(patsubst man/%.pod.1,man1/%.1,$(DOC_MAN1SRC))
DOC_MAN5	:= $(patsubst man/%.pod.5,man5/%.5,$(DOC_MAN5SRC))
DOC_MARKDOWN	:= $(wildcard misc/*.markdown)
DOC_HTML	:= $(patsubst %.markdown,html/%.html,$(DOC_MARKDOWN)) \
		   $(patsubst man/%.pod.1,html/man/%.1.html,$(DOC_MAN1SRC)) \
		   $(patsubst man/%.pod.5,html/man/%.5.html,$(DOC_MAN5SRC)) \
		   $(patsubst %.txt,html/%.txt,$(wildcard misc/*.txt)) \
		   html/hypercall/index.html
DOC_TXT         := $(patsubst %.txt,txt/%.txt,$(wildcard misc/*.txt)) \
		   $(patsubst %.markdown,txt/%.txt,$(DOC_MARKDOWN)) \
		   $(patsubst man/%.pod.1,txt/man/%.1.txt,$(DOC_MAN1SRC)) \
		   $(patsubst man/%.pod.5,txt/man/%.5.txt,$(DOC_MAN5SRC))

.PHONY: all
all: build

.PHONY: build
build: html txt man-pages
	@if which $(DOT) 1>/dev/null 2>/dev/null ; then              \
	$(MAKE) -C xen-api build ; else                              \
        echo "Graphviz (dot) not installed; skipping xen-api." ; fi
	rm -f *.aux *.dvi *.bbl *.blg *.glo *.idx *.ilg *.log *.ind *.toc

.PHONY: dev-docs
dev-docs: python-dev-docs

.PHONY: html
html: $(DOC_HTML) html/index.html

.PHONY: txt
txt: $(DOC_TXT)

.PHONY: python-dev-docs
python-dev-docs:
	@mkdir -v -p api/tools/python
	@set -e ; if which $(DOXYGEN) 1>/dev/null 2>/dev/null; then \
        echo "Running doxygen to generate Python tools APIs ... "; \
	$(DOXYGEN) Doxyfile;                                       \
	$(MAKE) -C api/tools/python/latex ; else                   \
        echo "Doxygen not installed; skipping python-dev-docs."; fi

.PHONY: man-pages
man-pages:
	@if which $(POD2MAN) 1>/dev/null 2>/dev/null; then \
	$(MAKE) $(DOC_MAN1) $(DOC_MAN5); else              \
	echo "pod2man not installed; skipping man-pages."; fi

man1/%.1: man/%.pod.1 Makefile
	$(INSTALL_DIR) $(@D)
	$(POD2MAN) --release=$(VERSION) --name=`echo $@ | sed 's/^man1.//'| \
		sed 's/.1//'` -s 1 -c "Xen" $< $@

man5/%.5: man/%.pod.5 Makefile
	$(INSTALL_DIR) $(@D)
	$(POD2MAN) --release=$(VERSION) --name=`echo $@ | sed 's/^man5.//'| \
		sed 's/.5//'` -s 5 -c "Xen" $< $@

.PHONY: clean
clean:
	$(MAKE) -C xen-api clean
	rm -rf .word_count *.aux *.dvi *.bbl *.blg *.glo *.idx *~ 
	rm -rf *.ilg *.log *.ind *.toc *.bak core
	rm -rf html txt
	rm -rf api
	rm -rf man5
	rm -rf man1

.PHONY: distclean
distclean: clean

.PHONY: install
install: all
	rm -rf $(DESTDIR)$(DOCDIR)
	$(INSTALL_DIR) $(DESTDIR)$(DOCDIR)

	$(MAKE) -C xen-api install

	$(INSTALL_DIR) $(DESTDIR)$(MANDIR)
	cp -dR man1 $(DESTDIR)$(MANDIR)
	cp -dR man5 $(DESTDIR)$(MANDIR)
	[ ! -d html ] || cp -dR html $(DESTDIR)$(DOCDIR)

html/index.html: $(DOC_HTML) ./gen-html-index INDEX
	perl -w -- ./gen-html-index -i INDEX html $(DOC_HTML)

html/%.html: %.markdown
	@$(INSTALL_DIR) $(@D)
	@set -e ; if which $(MARKDOWN) 1>/dev/null 2>/dev/null; then \
	echo "Running markdown to generate $*.html ... "; \
	$(MARKDOWN) $< > $@.tmp ; \
	$(call move-if-changed,$@.tmp,$@) ; else \
	echo "markdown not installed; skipping $*.html."; fi

html/%.txt: %.txt
	@$(INSTALL_DIR) $(@D)
	cp $< $@

html/man/%.1.html: man/%.pod.1 Makefile
	$(INSTALL_DIR) $(@D)
	$(POD2HTML) --infile=$< --outfile=$@.tmp
	$(call move-if-changed,$@.tmp,$@)

html/man/%.5.html: man/%.pod.5 Makefile
	$(INSTALL_DIR) $(@D)
	$(POD2HTML) --infile=$< --outfile=$@.tmp
	$(call move-if-changed,$@.tmp,$@)

html/hypercall/index.html: ./xen-headers
	rm -rf $(@D)
	@$(INSTALL_DIR) $(@D)
	./xen-headers -O $(@D) \
		-T 'arch-x86_64 - Xen public headers' \
		-X arch-ia64 -X arch-x86_32 -X xen-x86_32 -X arch-arm \
		../xen include/public include/xen/errno.h

-include html/hypercall/.deps

txt/%.txt: %.txt
	$(INSTALL_DIR) $(@D)
	cp $< $@.tmp
	$(call move-if-changed,$@.tmp,$@)

txt/%.txt: %.markdown
	$(INSTALL_DIR) $(@D)
	cp $< $@.tmp
	$(call move-if-changed,$@.tmp,$@)

txt/man/%.1.txt: man/%.pod.1 Makefile
	$(INSTALL_DIR) $(@D)
	$(POD2TEXT) $< $@.tmp
	$(call move-if-changed,$@.tmp,$@)

txt/man/%.5.txt: man/%.pod.5 Makefile
	$(INSTALL_DIR) $(@D)
	$(POD2TEXT) $< $@.tmp
	$(call move-if-changed,$@.tmp,$@)

