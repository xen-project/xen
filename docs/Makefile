
# Generic LaTeX makefile.
#
# Xfig and tgif diagrams should be in the fig/ subdirectory.
# DOCUMENTS should be a list of the target Postscript files.

DOCUMENTS = interface.ps interface.pdf user.ps user.pdf

GFX  = $(patsubst %.obj, %.eps, $(wildcard figs/*.obj))
GFX += $(patsubst %.fig, %.eps, $(wildcard figs/*.fig))

all: $(DOCUMENTS)

pristine: clean
	rm -f $(DOCUMENTS)

clean:
	rm -f .word_count *.aux *.dvi *.bbl *.blg *.glo *.idx *~ 
	rm -f *.ilg *.log *.ind *.toc *.bak core
	rm -f figs/*.eps $(DOCUMENTS)

install: $(DOCUMENTS)
	mkdir -p $(prefix)/usr/share/doc/xen
	cp -a $(DOCUMENTS) VBD-HOWTO.txt Xen-HOWTO.txt $(prefix)/usr/share/doc/xen

%.pdf: %.ps
	ps2pdf $< $@

%.ps: %.dvi $(GFX)
	dvips -Ppdf -G0 -o $@ $<

%.dvi: %.tex
	latex $*
	if [ -e $*.toc ] ; then latex $* ; fi

%.eps: %.fig
	fig2dev -L eps $< $@

%.eps: %.obj
	tgif -print -color -eps $<


