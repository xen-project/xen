OCAMLMAKEFILE = OCamlMakefile

XEN_ROOT    = ../../..
include $(XEN_ROOT)/tools/Rules.mk

# overwrite LDFLAGS from xen/tool/Rules.mk
# otherwise, ocamlmktop gets confused.
LDFLAGS     =

# force ocaml 3.08
OCAML_ROOT  = /usr/local
OCAMLC      = $(OCAML_ROOT)/bin/ocamlc
OCAMLMKTOP  = $(OCAML_ROOT)/bin/ocamlmktop
OCAMLLIBPATH= $(OCAML_ROOT)/lib/ocaml

INCLUDES   += -I $(XEN_XC)
INCLUDES   += -I $(XEN_LIBXC)
INCLUDES   += -I ../libxendebug
INCLUDES   += -I ./linux-2.6-module
INCLUDES   += -I $(OCAML_ROOT)/lib/ocaml

CFLAGS     += $(INCLUDES)
CFLAGS     += -Werror
CFLAGS     += -g

CLIBS      += xc
CLIBS      += xendebug

LIBDIRS    += $(XEN_LIBXC)
LIBDIRS    += ../libxendebug

LIBS       += unix str

# bc = byte-code, dc = debug byte-code
# patches = patch linux domU source code
.PHONY: all 
all : dc

SOURCES    += pdb_caml_xc.c 
SOURCES    += pdb_caml_domain.c pdb_caml_process.c
SOURCES    += pdb_caml_evtchn.c pdb_caml_xcs.c pdb_xen.c
SOURCES    += Util.ml Intel.ml 
SOURCES    += evtchn.ml evtchn.mli
SOURCES    += xcs.ml xcs.mli
SOURCES    += Xen_domain.ml Xen_domain.mli
SOURCES    += Domain.ml  Process.ml
SOURCES    += Domain.mli Process.mli
SOURCES    += PDB.ml debugger.ml server.ml

RESULT      = pdb

include $(OCAMLMAKEFILE)

PATCHDIR    = ./linux-2.6-patches
.PHONY: patches 
patches :
	make -C $(PATCHDIR) patches
