CC ?= gcc
OCAMLOPT ?= ocamlopt
OCAMLC ?= ocamlc
OCAMLMKLIB ?= ocamlmklib
OCAMLDEP ?= ocamldep
OCAMLLEX ?= ocamllex
OCAMLYACC ?= ocamlyacc

CFLAGS ?= -Wall -fPIC -O2 -Werror

CFLAGS += -I$(TOPLEVEL)/../include -I$(TOPLEVEL)/../libxc
CFLAGS += -I/usr/lib64/ocaml -I/usr/lib/ocaml

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
