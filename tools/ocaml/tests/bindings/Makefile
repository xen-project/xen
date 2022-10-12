XEN_ROOT = $(CURDIR)/../../../..
OCAML_TOPLEVEL = $(CURDIR)/../..
include $(OCAML_TOPLEVEL)/common.make

OBJS = main

OCAMLINCLUDE += \
	-I $(OCAML_TOPLEVEL)/libs/xb \
	-I $(OCAML_TOPLEVEL)/libs/mmap \
	-I $(OCAML_TOPLEVEL)/libs/xc \
	-I $(OCAML_TOPLEVEL)/libs/eventchn

LIBS = \
	unix.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/mmap $(OCAML_TOPLEVEL)/libs/mmap/xenmmap.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/eventchn $(OCAML_TOPLEVEL)/libs/eventchn/xeneventchn.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/xc $(OCAML_TOPLEVEL)/libs/xc/xenctrl.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/xb $(OCAML_TOPLEVEL)/libs/xb/xenbus.cmxa \
	-ccopt -L -ccopt $(XEN_ROOT)/tools/libs/ctrl

PROGRAMS = test-ocaml-bindings
OCAML_PROGRAM = test-ocaml-bindings

test-ocaml-bindings_LIBS = $(LIBS)
test-ocaml-bindings_MLSORTED = $(shell $(OCAMLDEP) -sort $(OBJS:=.ml))
test-ocaml-bindings_OBJS = $(test-ocaml-bindings_MLSORTED:.ml=)

all: test-ocaml-bindings

install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC)/tests
	$(INSTALL_PROG) test-ocaml-bindings $(DESTDIR)$(LIBEXEC)/tests

include $(OCAML_TOPLEVEL)/Makefile.rules
