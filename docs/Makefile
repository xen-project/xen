XEN_ROOT=$(CURDIR)/..
include $(XEN_ROOT)/Config.mk
-include $(XEN_ROOT)/config/Docs.mk

VERSION		:= $(shell $(MAKE) -C $(XEN_ROOT)/xen --no-print-directory xenversion)

DOC_ARCHES      := arm x86_32 x86_64

# Documentation sources to build
MAN1SRC-y := $(sort $(wildcard man/xl*.pod.1))
MAN1SRC-y += $(sort $(wildcard man/xenstore*.pod.1))

MAN5SRC-y := $(sort $(wildcard man/xl*.pod.5))

MARKDOWNSRC-y := $(sort $(wildcard misc/*.markdown))

TXTSRC-y := $(sort $(wildcard misc/*.txt))

PANDOCSRC-y := $(sort $(wildcard specs/*.pandoc))

# Documentation targets
DOC_MAN1 := $(patsubst man/%.pod.1,man1/%.1,$(MAN1SRC-y))
DOC_MAN5 := $(patsubst man/%.pod.5,man5/%.5,$(MAN5SRC-y))
DOC_HTML := $(patsubst %.markdown,html/%.html,$(MARKDOWNSRC-y)) \
            $(patsubst %.pandoc,html/%.html,$(PANDOCSRC-y)) \
            $(patsubst man/%.pod.1,html/man/%.1.html,$(MAN1SRC-y)) \
            $(patsubst man/%.pod.5,html/man/%.5.html,$(MAN5SRC-y)) \
            $(patsubst %.txt,html/%.txt,$(TXTSRC-y)) \
            $(patsubst %,html/hypercall/%/index.html,$(DOC_ARCHES))
DOC_TXT  := $(patsubst %.txt,txt/%.txt,$(TXTSRC-y)) \
            $(patsubst %.markdown,txt/%.txt,$(MARKDOWNSRC-y)) \
            $(patsubst %.pandoc,txt/%.txt,$(PANDOCSRC-y)) \
            $(patsubst man/%.pod.1,txt/man/%.1.txt,$(MAN1SRC-y)) \
            $(patsubst man/%.pod.5,txt/man/%.5.txt,$(MAN5SRC-y))
DOC_PDF  := $(patsubst %.markdown,pdf/%.pdf,$(MARKDOWNSRC-y)) \
            $(patsubst %.pandoc,pdf/%.pdf,$(PANDOCSRC-y))

# Top level build targets
.PHONY: all
all: build

.PHONY: build
build: html txt pdf man-pages figs

.PHONY: html
html: $(DOC_HTML) html/index.html

.PHONY: txt
txt: $(DOC_TXT)

.PHONY: figs
figs:
ifneq ($(FIG2DEV),)
	set -x; $(MAKE) -C figs
else
	@echo "fig2dev (transfig) not installed; skipping figs."
endif

.PHONY: man-pages
man-pages: $(DOC_MAN1) $(DOC_MAN5)

.PHONY: pdf
pdf: $(DOC_PDF)

.PHONY: clean
clean:
	$(MAKE) -C figs clean
	rm -rf .word_count *.aux *.dvi *.bbl *.blg *.glo *.idx *~
	rm -rf *.ilg *.log *.ind *.toc *.bak *.tmp core
	rm -rf html txt pdf
	rm -rf man5
	rm -rf man1

.PHONY: distclean
distclean: clean
	rm -rf $(XEN_ROOT)/config/Docs.mk config.log config.status config.cache \
		autom4te.cache

# Top level install targets
.PHONY: install-man-pages
install-man-pages: man-pages
	$(INSTALL_DIR) $(DESTDIR)$(mandir)
	cp -R man1 $(DESTDIR)$(mandir)
	cp -R man5 $(DESTDIR)$(mandir)

.PHONY: install-html
install-html: html txt figs
	$(INSTALL_DIR) $(DESTDIR)$(docdir)
	[ ! -d html ] || cp -R html $(DESTDIR)$(docdir)

.PHONY: install
install: install-man-pages install-html

# Individual file build targets
man1/%.1: man/%.pod.1 Makefile
ifneq ($(POD2MAN),)
	@$(INSTALL_DIR) $(@D)
	$(POD2MAN) --release=$(VERSION) --name=$* -s 1 -c "Xen" $< $@
else
	@echo "pod2man not installed; skipping $@"
endif

man5/%.5: man/%.pod.5 Makefile
ifneq ($(POD2MAN),)
	@$(INSTALL_DIR) $(@D)
	$(POD2MAN) --release=$(VERSION) --name=$* -s 5 -c "Xen" $< $@
else
	@echo "pod2man not installed; skipping $@"
endif

html/index.html: $(DOC_HTML) $(CURDIR)/gen-html-index INDEX
	$(PERL) -w -- $(CURDIR)/gen-html-index -i INDEX html $(DOC_HTML)

html/%.html: %.markdown
ifneq ($(MARKDOWN),)
	@$(INSTALL_DIR) $(@D)
	$(MARKDOWN) $< > $@
else
	@echo "markdown not installed; skipping $@"
endif

html/%.txt: %.txt
	@$(INSTALL_DIR) $(@D)
	$(INSTALL_DATA) $< $@

html/man/%.1.html: man/%.pod.1 Makefile
ifneq ($(POD2HTML),)
	@$(INSTALL_DIR) $(@D)
	$(POD2HTML) --infile=$< --outfile=$@
else
	@echo "pod2html not installed; skipping $@"
endif

html/man/%.5.html: man/%.pod.5 Makefile
ifneq ($(POD2HTML),)
	@$(INSTALL_DIR) $(@D)
	$(POD2HTML) --infile=$< --outfile=$@
else
	@echo "pod2html not installed; skipping $@"
endif

# For non-x86 arches exclude the subarch whole x86 arch.
$(foreach i,$(filter-out x86_32 x86_64,$(DOC_ARCHES)),html/hypercall/$(i)/index.html): EXTRA_EXCLUDE := -X arch-x86

html/hypercall/%/index.html: $(CURDIR)/xen-headers Makefile
	rm -rf $(@D)
	$(INSTALL_DIR) $(@D)
	$(PERL) -w $(CURDIR)/xen-headers -O $(@D) \
		-T 'arch-$* - Xen public headers' \
		$(patsubst %,-X arch-%,$(filter-out $*,$(DOC_ARCHES))) \
		$(patsubst %,-X xen-%,$(filter-out $*,$(DOC_ARCHES))) \
		$(EXTRA_EXCLUDE) \
		$(XEN_ROOT)/xen include/public include/xen/errno.h

-include $(wildcard html/hypercall/*/.deps)

txt/%.txt: %.txt
	@$(INSTALL_DIR) $(@D)
	$(INSTALL_DATA) $< $@

txt/%.txt: %.markdown
	@$(INSTALL_DIR) $(@D)
	$(INSTALL_DATA) $< $@

txt/man/%.1.txt: man/%.pod.1 Makefile
ifneq ($(POD2TEXT),)
	@$(INSTALL_DIR) $(@D)
	$(POD2TEXT) $< $@
else
	@echo "pod2text not installed; skipping $@"
endif

txt/man/%.5.txt: man/%.pod.5 Makefile
ifneq ($(POD2TEXT),)
	@$(INSTALL_DIR) $(@D)
	$(POD2TEXT) $< $@
else
	@echo "pod2text not installed; skipping $@"
endif

pdf/%.pdf: %.markdown
ifneq ($(PANDOC),)
	@$(INSTALL_DIR) $(@D)
	$(PANDOC) --number-sections --toc --standalone $< --output $@
else
	@echo "pandoc not installed; skipping $@"
endif

pdf/%.pdf txt/%.txt html/%.html: %.pandoc
ifneq ($(PANDOC),)
	@$(INSTALL_DIR) $(@D)
	$(PANDOC) --number-sections --toc --standalone $< --output $@
else
	@echo "pandoc not installed; skipping $@"
endif

ifeq (,$(findstring clean,$(MAKECMDGOALS)))
$(XEN_ROOT)/config/Docs.mk:
	$(error You have to run ./configure before building docs)
endif
