# -*- mode: Makefile; -*-

ifndef VNET_ROOT
export VNET_ROOT = $(shell pwd)
include $(VNET_ROOT)/Make.env
endif

.PHONY: all compile install dist clean pristine
.PHONY: gc-all gc-install gc-clean

SUBDIRS:=
SUBDIRS+= examples
SUBDIRS+= gc
SUBDIRS+= libxutil
SUBDIRS+= vnetd
SUBDIRS+= vnet-module

all: compile

gc.tar.gz:
	wget http://www.hpl.hp.com/personal/Hans_Boehm/gc/gc_source/$@

gc: gc.tar.gz
	tar xfz gc.tar.gz
	ln -sf gc?.? gc

$(GC_LIB_A): gc
	(cd gc && ./configure --prefix=$(GC_DIR) )
	make -C gc
	DESTDIR="" make -C gc install

gc-all: $(GC_LIB_A)

gc-install:

gc-clean:
	-@$(RM) -r gc?.? gc

submak = $(MAKE) -C $(patsubst %-$(1),%,$(@)) $(1)
subtgt = $(patsubst %,%-$(1),$(SUBDIRS))

%-all:
	$(call submak,all)

%-clean:
	-$(call submak,clean)

%-install:
	$(call submak,install)

compile: $(call subtgt,all)

install: DESTDIR=
install: dist

dist: compile $(call subtgt,install)

clean: $(call subtgt,clean)
	-@$(RM) -r build

pristine: clean
	-@$(RM) gc.tar.gz
