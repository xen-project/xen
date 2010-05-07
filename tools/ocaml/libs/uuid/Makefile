TOPLEVEL=../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

OBJS = uuid
INTF = $(foreach obj, $(OBJS),$(obj).cmi)
LIBS = uuid.cma uuid.cmxa

all: $(INTF) $(LIBS) $(PROGRAMS)

bins: $(PROGRAMS)

libs: $(LIBS)

uuid_OBJS = $(OBJS)
OCAML_NOC_LIBRARY = uuid

.PHONY: install
install: $(LIBS) META
	ocamlfind install -destdir $(DESTDIR)$(shell ocamlfind printconf destdir) -ldconf ignore uuid META $(INTF) $(LIBS) *.a *.cmx

.PHONY: uninstall
uninstall:
	ocamlfind remove uuid

include $(TOPLEVEL)/Makefile.rules

