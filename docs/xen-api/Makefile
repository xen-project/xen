#!/usr/bin/make -f

XEN_ROOT=../..
include $(XEN_ROOT)/Config.mk
include $(XEN_ROOT)/docs/Docs.mk


TEX := $(wildcard *.tex)
EPS := $(wildcard *.eps)
EPSDOT := $(patsubst %.dot,%.eps,$(wildcard *.dot))

.PHONY: all
all: build

.PHONY: build
build: xenapi.pdf xenapi.ps

install:
	$(INSTALL_DIR) $(DESTDIR)$(pkgdocdir)/ps
	$(INSTALL_DIR) $(DESTDIR)$(pkgdocdir)/pdf

	cp xenapi.ps $(DESTDIR)$(pkgdocdir)/ps
	cp xenapi.pdf $(DESTDIR)$(pkgdocdir)/pdf


xenapi.dvi: $(TEX) $(EPS) $(EPSDOT)
	$(LATEX) xenapi.tex
	$(LATEX) xenapi.tex
	rm -f *.aux *.log

%.pdf: %.ps
	$(PS2PDF) $< $@

%.ps: %.dvi
	$(DVIPS) $< -o $@

%.eps: %.dot
	$(DOT) -Tps $< >$@

.PHONY: clean
clean:
	rm -f *.pdf *.ps *.dvi *.aux *.log $(EPSDOT)
