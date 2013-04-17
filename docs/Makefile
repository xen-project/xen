#!/usr/bin/make -f

XEN_ROOT=$(CURDIR)/..
include $(XEN_ROOT)/Config.mk
-include $(XEN_ROOT)/config/Docs.mk

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
build: html txt man-pages figs

.PHONY: html
html: $(DOC_HTML) html/index.html

.PHONY: txt
txt:
ifdef POD2TEXT
	$(MAKE) $(DOC_TXT)
else
	@echo "pod2text not installed; skipping text outputs."
endif

.PHONY: figs
figs:
ifdef FIG2DEV
	set -x; $(MAKE) -C figs
else
	@echo "fig2dev (transfig) not installed; skipping figs."
endif

.PHONY: man-pages
man-pages:
ifdef POD2MAN
	$(MAKE) $(DOC_MAN1) $(DOC_MAN5)
else
	@echo "pod2man not installed; skipping man-pages."
endif

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
	$(MAKE) -C figs clean
	rm -rf .word_count *.aux *.dvi *.bbl *.blg *.glo *.idx *~ 
	rm -rf *.ilg *.log *.ind *.toc *.bak core
	rm -rf html txt
	rm -rf man5
	rm -rf man1

.PHONY: distclean
distclean: clean
	rm -rf ../config/Docs.mk config.log config.status config.cache \
		autom4te.cache

.PHONY: install
install: all
	rm -rf $(DESTDIR)$(DOCDIR)
	$(INSTALL_DIR) $(DESTDIR)$(DOCDIR)

	$(INSTALL_DIR) $(DESTDIR)$(MANDIR)
	cp -R man1 $(DESTDIR)$(MANDIR)
	cp -R man5 $(DESTDIR)$(MANDIR)
	[ ! -d html ] || cp -R html $(DESTDIR)$(DOCDIR)

html/index.html: $(DOC_HTML) ./gen-html-index INDEX
	perl -w -- ./gen-html-index -i INDEX html $(DOC_HTML)

html/%.html: %.markdown
	$(INSTALL_DIR) $(@D)
ifdef MARKDOWN
	@echo "Running markdown to generate $*.html ... "
	$(MARKDOWN) $< > $@.tmp ; \
	$(call move-if-changed,$@.tmp,$@)
else
	@echo "markdown not installed; skipping $*.html."
endif

html/%.txt: %.txt
	$(INSTALL_DIR) $(@D)
	cp $< $@

html/man/%.1.html: man/%.pod.1 Makefile
	$(INSTALL_DIR) $(@D)
ifdef POD2HTML
	$(POD2HTML) --infile=$< --outfile=$@.tmp
	$(call move-if-changed,$@.tmp,$@)
else
	@echo "pod2html not installed; skipping $<."
endif

html/man/%.5.html: man/%.pod.5 Makefile
	$(INSTALL_DIR) $(@D)
ifdef POD2HTML
	$(POD2HTML) --infile=$< --outfile=$@.tmp
	$(call move-if-changed,$@.tmp,$@)
else
	@echo "pod2html not installed; skipping $<."
endif

html/hypercall/index.html: ./xen-headers
	rm -rf $(@D)
	$(INSTALL_DIR) $(@D)
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
ifdef POD2TEXT
	$(POD2TEXT) $< $@.tmp
	$(call move-if-changed,$@.tmp,$@)
else
	@echo "pod2text not installed; skipping $<."
endif

txt/man/%.5.txt: man/%.pod.5 Makefile
	$(INSTALL_DIR) $(@D)
ifdef POD2TEXT
	$(POD2TEXT) $< $@.tmp
	$(call move-if-changed,$@.tmp,$@)
else
	@echo "pod2text not installed; skipping $<."
endif

ifeq (,$(findstring clean,$(MAKECMDGOALS)))
$(XEN_ROOT)/config/Docs.mk:
	$(error You have to run ./configure before building docs)
endif
