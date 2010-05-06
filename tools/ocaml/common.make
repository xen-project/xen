CC ?= gcc
OCAMLOPT ?= ocamlopt
OCAMLC ?= ocamlc
OCAMLMKLIB ?= ocamlmklib
OCAMLDEP ?= ocamldep
OCAMLLEX ?= ocamllex
OCAMLYACC ?= ocamlyacc

CFLAGS ?= -Wall -fPIC -O2

XEN_ROOT ?= $(TOPLEVEL)/../xen-unstable.hg
XEN_DIST_ROOT ?= $(XEN_ROOT)/dist/install
CFLAGS += -I$(XEN_DIST_ROOT)/usr/include

OCAMLOPTFLAG_G := $(shell $(OCAMLOPT) -h 2>&1 | sed -n 's/^  *\(-g\) .*/\1/p')
OCAMLOPTFLAGS = $(OCAMLOPTFLAG_G) -ccopt "$(LDFLAGS)" -dtypes $(OCAMLINCLUDE) -cc $(CC) -w F -warn-error F
OCAMLCFLAGS += -g $(OCAMLINCLUDE) -w F -warn-error F

#LDFLAGS = -cclib -L./

DESTDIR ?= /
VERSION := echo 0.0

OCAMLABI = $(shell $(OCAMLC) -version)
OCAMLLIBDIR = $(shell $(OCAMLC) -where)
OCAMLDESTDIR ?= $(OCAMLLIBDIR)

o= >$@.new && mv -f $@.new $@
