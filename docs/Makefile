#!/usr/bin/make -f

INSTALL		= install
INSTALL_DIR	= $(INSTALL) -d -m0755

PS2PDF		:= ps2pdf
DVIPS		:= dvips
LATEX		:= latex
FIG2DEV		:= fig2dev
TGIF		:= tgif
LATEX2HTML	:= latex2html

package		= xen
docdir		= /usr/share/doc
pkgdocdir	= $(docdir)/$(package)

DOC_TEX		:= $(wildcard src/*.tex)
DOC_PS		:= $(patsubst src/%.tex,ps/%.ps,$(DOC_TEX))
DOC_PDF		:= $(patsubst src/%.tex,pdf/%.pdf,$(DOC_TEX))
DOC_HTML	:= $(patsubst src/%.tex,html/%/index.html,$(DOC_TEX))

GFX  = $(patsubst %.obj, %.eps, $(wildcard figs/*.obj))
GFX += $(patsubst %.fig, %.eps, $(wildcard figs/*.fig))

all: ps pdf html
	rm -f *.aux *.dvi *.bbl *.blg *.glo *.idx *.ilg *.log *.ind *.toc

ps: $(DOC_PS)

pdf: $(DOC_PDF)

html: $(DOC_HTML)

clean:
	rm -rf .word_count *.aux *.dvi *.bbl *.blg *.glo *.idx *~ 
	rm -rf *.ilg *.log *.ind *.toc *.bak core
	rm -rf $(GFX) ps pdf html

install: all
	rm -rf $(prefix)$(pkgdocdir)
	$(INSTALL_DIR) $(prefix)$(pkgdocdir)
	cp -dR ps $(prefix)$(pkgdocdir)
	cp -dR pdf $(prefix)$(pkgdocdir)
	cp -dR html $(prefix)$(pkgdocdir)

pdf/%.pdf: ps/%.ps
	$(INSTALL_DIR) $(@D)
	$(PS2PDF) $< $@.new
	mv $@.new $@

ps/%.ps: %.dvi
	$(INSTALL_DIR) $(@D)
	$(DVIPS) -Ppdf -G0 -o $@.new $<
	mv $@.new $@

%.dvi: src/%.tex $(GFX)
	$(LATEX) $< >/dev/null
	if [ -e $*.toc ] ; then $(LATEX) $< >/dev/null ; fi

%.eps: %.fig
	$(FIG2DEV) -L eps $< $@

%.eps: %.obj
	$(TGIF) -print -color -eps $<

html/%/index.html: src/%.tex
	$(INSTALL_DIR) $(@D)
	$(LATEX2HTML) -split 0 -show_section_numbers -toc_depth 3 -nonavigation \
	-numbered_footnotes -local_icons -noinfo -math -dir $(@D) \
	$< 1>/dev/null 2>/dev/null
