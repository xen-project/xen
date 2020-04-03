XEN_ROOT=$(CURDIR)/..
include $(XEN_ROOT)/Config.mk
-include $(XEN_ROOT)/config/Docs.mk

VERSION		:= $(shell $(MAKE) -C $(XEN_ROOT)/xen --no-print-directory xenversion)
DATE		:= $(shell date +%Y-%m-%d)

DOC_ARCHES      := arm x86_32 x86_64
MAN_SECTIONS    := 1 5 7 8

# Documentation sources to build
MAN-SRC-y := $(sort $(basename $(wildcard man/*.pod man/*.pandoc)))

RST-SRC-y := $(sort $(filter-out %index.rst,$(shell find * -type f -name '*.rst' -print)))

TXTSRC-y := $(sort $(shell find misc -name '*.txt' -print))

PANDOCSRC-y := $(sort $(shell find designs/ features/ misc/ process/ specs/ \( -name '*.pandoc' -o -name '*.md' \) -print))

# Documentation targets
$(foreach i,$(MAN_SECTIONS), \
  $(eval DOC_MAN$(i) := $(patsubst man/%.$(i),man$(i)/%.$(i), \
                                   $(filter %.$(i),$(MAN-SRC-y)))))

DOC_HTML := html/SUPPORT.html \
            $(patsubst %.pandoc,html/%.html,$(PANDOCSRC-y)) \
            $(patsubst %.md,html/%.html,$(PANDOCSRC-y)) \
            $(patsubst %.rst,html/%.html,$(RST-SRC-y)) \
            $(patsubst %,html/%.html,$(MAN-SRC-y)) \
            $(patsubst %.txt,html/%.txt,$(TXTSRC-y)) \
            $(patsubst %,html/hypercall/%/index.html,$(DOC_ARCHES))
DOC_TXT  := $(patsubst %.txt,txt/%.txt,$(TXTSRC-y)) \
            $(patsubst %.pandoc,txt/%.txt,$(PANDOCSRC-y)) \
            $(patsubst %.md,txt/%.txt,$(PANDOCSRC-y)) \
            $(patsubst %.rst,txt/%.txt,$(RST-SRC-y)) \
            $(patsubst %,txt/%.txt,$(MAN-SRC-y))
DOC_PDF  := $(patsubst %.pandoc,pdf/%.pdf,$(PANDOCSRC-y)) \
            $(patsubst %.md,pdf/%.pdf,$(PANDOCSRC-y)) \
            $(patsubst %.rst,pdf/%.pdf,$(RST-SRC-y))

# Top level build targets
.PHONY: all
all: build

.PHONY: build
build: html txt pdf man-pages figs

.PHONY: sphinx-html
sphinx-html:
	sphinx-build -b html . sphinx/html

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

.PHONY: pdf
pdf: $(DOC_PDF)

.PHONY: clean
clean: clean-man-pages
	$(MAKE) -C figs clean
	rm -rf .word_count *.aux *.dvi *.bbl *.blg *.glo *.idx *~
	rm -rf *.ilg *.log *.ind *.toc *.bak *.tmp core
	rm -rf html txt pdf sphinx/html

.PHONY: distclean
distclean: clean
	rm -rf $(XEN_ROOT)/config/Docs.mk config.log config.status config.cache \
		autom4te.cache

# Top level install targets

.PHONY: man-pages install-man-pages clean-man-pages uninstall-man-pages

# Metarules for generating manpages.  Run with $(1) substitued for section
define GENERATE_MANPAGE_RULES

# Real manpages
man$(1)/%.$(1): man/%.$(1).pod Makefile
ifneq ($(POD2MAN),)
	@$(INSTALL_DIR) $$(@D)
	$(POD2MAN) --release=$(VERSION) --name=$$* -s $(1) -c "Xen" $$< $$@
else
	@echo "pod2man not installed; skipping $$@"
endif

man$(1)/%.$(1): man/%.$(1).pandoc Makefile
ifneq ($(PANDOC),)
	@$(INSTALL_DIR) $$(@D)
	$(PANDOC) --standalone -V title=$$* -V section=$(1) \
		      -V date="$(DATE)" -V footer="$(VERSION)" \
			  -V header=Xen $$< -t man --output $$@
else
	@echo "pandoc not installed; skipping $$@"
endif

# HTML manpages
html/man/%.$(1).html: man/%.$(1).pod Makefile
ifneq ($(POD2HTML),)
	@$(INSTALL_DIR) $$(@D)
	# Fix up links between man-pages
	# 1) L<xl(1)> -> L<xl(1)|relative:xl.1.html>
	# 2) <a href="relative:xl.1.html"> -> <a href="xl.1.html">
	sed -r -e 's%L<([^>]+)\(([1-9])\)>%L<\1(\2)|relative:\1.\2.html>%g' $$< | \
		$(POD2HTML) | \
		sed -r -e 's%( href=")relative:%\1%g' > $$@
else
	@echo "pod2html not installed; skipping $$@"
endif

html/man/%.$(1).html: man/%.$(1).pandoc Makefile
ifneq ($(PANDOC),)
	@$(INSTALL_DIR) $$(@D)
	$(PANDOC) --standalone $$< -t html --toc --output $$@
else
	@echo "pandoc not installed; skipping $$@"
endif

# Text manpages
txt/man/%.$(1).txt: man/%.$(1).pod Makefile
ifneq ($(POD2TEXT),)
	@$(INSTALL_DIR) $$(@D)
	$(POD2TEXT) $$< $$@
else
	@echo "pod2text not installed; skipping $$@"
endif

txt/man/%.$(1).txt: man/%.$(1).pandoc Makefile
ifneq ($(PANDOC),)
	@$(INSTALL_DIR) $$(@D)
	$(PANDOC) --standalone $$< -t plain --output $$@
else
	@echo "pandoc not installed; skipping $$@"
endif

# Build
.PHONY: man$(1)-pages
man$(1)-pages: $$(DOC_MAN$(1))

# Install
.PHONY: install-man$(1)-pages
install-man$(1)-pages: man$(1)-pages
	$(INSTALL_DIR) $(DESTDIR)$(mandir)
	cp -r man$(1) $(DESTDIR)$(mandir)

# Clean
.PHONY: clean-man$(1)-pages
clean-man$(1)-pages:
	rm -rf man$(1)

# Uninstall
.PHONY: uninstall-man$(1)-pages
uninstall-man$(1)-pages:
	rm -f $(addprefix $(DESTDIR)$(mandir)/,$(DOC_MAN$(1)))

# Link buld/install/clean to toplevel rules
man-pages: man$(1)-pages
install-man-pages: install-man$(1)-pages
clean-man-pages: clean-man$(1)-pages
uninstall-man-pages: uninstall-man$(1)-pages

endef

# Generate manpage rules for each section
$(foreach i,$(MAN_SECTIONS),$(eval $(call GENERATE_MANPAGE_RULES,$(i))))

.PHONY: install-html
install-html: html txt figs
	$(INSTALL_DIR) $(DESTDIR)$(docdir)
	[ ! -d html ] || cp -R html $(DESTDIR)$(docdir)

.PHONY: install
install: install-man-pages install-html

.PHONY: uninstall-html
uninstall-html:
	rm -rf $(DESTDIR)$(docdir)

.PHONY: uninstall
uninstall: uninstall-man-pages uninstall-html

# Individual file build targets
html/index.html: $(DOC_HTML) $(CURDIR)/gen-html-index INDEX
	$(PERL) -w -- $(CURDIR)/gen-html-index -i INDEX html $(DOC_HTML)

html/%.txt: %.txt
	@$(INSTALL_DIR) $(@D)
	$(INSTALL_DATA) $< $@


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

# Metarule for generating pandoc rules.
define GENERATE_PANDOC_RULE_RAW
$(1): $(2)
ifneq ($(PANDOC),)
	@$(INSTALL_DIR) $$(@D)
	$(PANDOC) --number-sections --toc --standalone $$< --output $$@
else
	@echo "pandoc not installed; skipping $$@"
endif
endef
define GENERATE_PANDOC_RULE
# $(1) is the target documentation format. $(2) is the source format.
$(call GENERATE_PANDOC_RULE_RAW,$(1)/%.$(1),%.$(2))
endef

$(foreach dst-fmt,pdf txt html,\
$(foreach src-fmt,pandoc md rst,\
$(eval $(call GENERATE_PANDOC_RULE,$(dst-fmt),$(src-fmt)))))

$(eval $(call GENERATE_PANDOC_RULE_RAW,html/SUPPORT.html,$(XEN_ROOT)/SUPPORT.md))

ifeq (,$(findstring clean,$(MAKECMDGOALS)))
$(XEN_ROOT)/config/Docs.mk:
	$(error You have to run ./configure before building docs)
endif
