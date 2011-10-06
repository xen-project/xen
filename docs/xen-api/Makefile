#!/usr/bin/make -f

XEN_ROOT=$(CURDIR)/../..
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
	$(INSTALL_DIR) $(DESTDIR)$(DOCDIR)/ps
	$(INSTALL_DIR) $(DESTDIR)$(DOCDIR)/pdf

	[ -e xenapi.ps ] && cp xenapi.ps $(DESTDIR)$(DOCDIR)/ps || true
	[ -e xenapi.pdf ] && cp xenapi.pdf $(DESTDIR)$(DOCDIR)/pdf || true

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

xenapi-datamodel-graph.eps: xenapi-datamodel-graph.dot
	$(NEATO) -Goverlap=false -Tps $< >$@

.PHONY: clean
clean:
	rm -f *.pdf *.ps *.dvi *.aux *.log *.out $(EPSDOT)
