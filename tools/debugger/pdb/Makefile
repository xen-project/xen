OCAMLMAKEFILE = OCamlMakefile

XEN_ROOT    = ../../..
include $(XEN_ROOT)/tools/Rules.mk

# overwrite LDFLAGS from xen/tool/Rules.mk
# otherwise, ocamlmktop gets confused.
LDFLAGS     =

OCAML_ROOT=/usr/local
# force ocaml 3.08
# OCAML_ROOT  = /anfs/nos1/ach61/ocaml

OCAMLC      = $(OCAML_ROOT)/bin/ocamlc
OCAMLMKTOP  = $(OCAML_ROOT)/bin/ocamlmktop
OCAMLLIBPATH= $(OCAML_ROOT)/lib/ocaml

INCLUDES   += -I $(XEN_XC)
INCLUDES   += -I $(XEN_LIBXC)
INCLUDES   += -I ../libxendebug
INCLUDES   += -I $(OCAML_ROOT)/lib/ocaml

CFLAGS     += $(INCLUDES)
CFLAGS     += -Wall
CFLAGS     += -Werror
CFLAGS     += -g

CLIBS      += xc
CLIBS      += xendebug
CLIBS      += pdb

LIBDIRS    += $(XEN_LIBXC)
LIBDIRS    += $(XEN_LIBXUTIL)
LIBDIRS    += ../libxendebug
LIBDIRS    += .

LIBS       += unix str

PRE_TARGETS = libpdb.a

all : bc

libpdb.a : pdb_xen.o
	ar rc $@ $^
	ranlib $@

SOURCES    += pdb_caml_xc.c pdb_xen.c
SOURCES    += Util.ml Intel.ml 
SOURCES    += evtchn.ml evtchn.mli
SOURCES    += Domain.ml  Process.ml
SOURCES    += Domain.mli Process.mli
SOURCES    += PDB.ml debugger.ml server.ml
RESULT      = pdb

include $(OCAMLMAKEFILE)

