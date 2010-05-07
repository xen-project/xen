TOPLEVEL=../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

CFLAGS += -I../mmap
OCAMLINCLUDE += -I ../mmap

.NOTPARALLEL:
# Ocaml is such a PITA!

PREINTF = op.cmi partial.cmi packet.cmi
PREOBJS = op partial packet xs_ring
PRELIBS = $(foreach obj, $(PREOBJS),$(obj).cmo) $(foreach obj,$(PREOJBS),$(obj).cmx)
OBJS = op partial packet xs_ring xb
INTF = op.cmi packet.cmi xb.cmi
LIBS = xb.cma xb.cmxa

ALL_OCAML_OBJS = $(OBJS) $(PREOJBS)

all: $(PREINTF) $(PRELIBS) $(INTF) $(LIBS) $(PROGRAMS)

bins: $(PROGRAMS)

libs: $(LIBS)

xb_OBJS = $(OBJS)
xb_C_OBJS = xs_ring_stubs xb_stubs
OCAML_LIBRARY = xb

%.mli: %.ml
	$(E) " MLI       $@"
	$(Q)$(OCAMLC) -i $< $o

.PHONY: install
install: $(LIBS) META
	ocamlfind install -destdir $(DESTDIR)$(shell ocamlfind printconf destdir) -ldconf ignore xb META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	ocamlfind remove xb

include $(TOPLEVEL)/Makefile.rules
