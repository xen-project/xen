
DOC_TEX  := $(wildcard src/*.tex)
DOC_PS   := $(patsubst src/%.tex,ps/%.ps,$(DOC_TEX))
DOC_PDF  := $(patsubst src/%.tex,pdf/%.pdf,$(DOC_TEX))
DOC_HTML := $(patsubst src/%.tex,html/%/index.html,$(DOC_TEX))

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
	mkdir -p $(prefix)/usr/share/doc/xen
	cp -dR ps $(prefix)/usr/share/doc/xen
	cp -dR pdf $(prefix)/usr/share/doc/xen
	cp -dR html $(prefix)/usr/share/doc/xen

pdf/%.pdf: ps/%.ps
	mkdir -p pdf ; ps2pdf $< $@

ps/%.ps: %.dvi $(GFX)
	mkdir -p ps ; dvips -Ppdf -G0 -o $@ $<

%.dvi: src/%.tex
	latex $< >/dev/null
	if [ -e $*.toc ] ; then latex $< >/dev/null ; fi

%.eps: %.fig
	fig2dev -L eps $< $@

%.eps: %.obj
	tgif -print -color -eps $<

html/%/index.html: src/%.tex
	mkdir -p html/$*
	latex2html -split 0 -show_section_numbers -toc_depth 3 -nonavigation \
	-noinfo -math -dir html/$* $< 1>/dev/null 2>/dev/null
