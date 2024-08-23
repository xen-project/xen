include $(XEN_ROOT)/tools/Rules.mk

CC ?= gcc
OCAMLOPT ?= ocamlopt
OCAMLC ?= ocamlc
OCAMLMKLIB ?= ocamlmklib
OCAMLDEP ?= ocamldep
OCAMLLEX ?= ocamllex
OCAMLYACC ?= ocamlyacc
OCAMLFIND ?= ocamlfind

CFLAGS += -fPIC -I$(shell ocamlc -where)

OCAMLOPTFLAGS = -g -ccopt "$(LDFLAGS)" -dtypes $(OCAMLINCLUDE) -w F -warn-error F
OCAMLCFLAGS += -g $(OCAMLINCLUDE) -w F -warn-error F

VERSION := $(shell $(XEN_ROOT)/version.sh $(XEN_ROOT)/xen/Makefile)

OCAMLDESTDIR ?= $(DESTDIR)$(shell $(OCAMLFIND) printconf destdir)
