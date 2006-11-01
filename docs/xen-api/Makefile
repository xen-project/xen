TEX := $(wildcard *.tex)
EPS := $(wildcard *.eps)
EPSDOT := $(patsubst %.dot,%.eps,$(wildcard *.dot))

.PHONY: all
all: xenapi.pdf xenapi.ps

xenapi.dvi: $(TEX) $(EPS) $(EPSDOT)
	latex xenapi.tex
	latex xenapi.tex

%.pdf: %.ps
	ps2pdf $< $@

%.ps: %.dvi
	dvips $< -o $@

%.eps: %.dot
	dot -Tps $< >$@

.PHONY: clean
clean:
	rm -f *.pdf *.ps *.dvi *.aux *.log $(EPSDOT)
