TOPLEVEL=../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

OCAMLINCLUDE += -I ../xb/

.NOTPARALLEL:
# Ocaml is such a PITA!

PREINTF = xsraw.cmi xst.cmi
PREOBJS = queueop xsraw xst
PRELIBS = $(foreach obj, $(PREOBJS),$(obj).cmo) $(foreach obj,$(PREOJBS),$(obj).cmx)
OBJS = queueop xsraw xst xs
INTF = xsraw.cmi xst.cmi xs.cmi
LIBS = xs.cma xs.cmxa

all: $(PREINTF) $(PRELIBS) $(INTF) $(LIBS) $(PROGRAMS)

bins: $(PROGRAMS)

libs: $(LIBS)

xs_OBJS = $(OBJS)
OCAML_NOC_LIBRARY = xs

#xs.cmxa: $(foreach obj,$(OBJS),$(obj).cmx)
#	$(E) " MLLIB     $@"
#	$(Q)$(OCAMLOPT) $(OCAMLOPTFLAGS) -a -o $@ $(foreach obj,$(OBJS),$(obj).cmx)
#
#xs.cma: $(foreach obj,$(OBJS),$(obj).cmo)
#	$(E) " MLLIB     $@"
#	$(Q)$(OCAMLC) -a -o $@ $(foreach obj,$(OBJS),$(obj).cmo)

.PHONY: install
install: $(LIBS) META
	ocamlfind install -destdir $(DESTDIR)$(shell ocamlfind printconf destdir) -ldconf ignore xs META $(INTF) xs.mli xst.mli xsraw.mli $(LIBS) *.a *.cmx

.PHONY: uninstall
uninstall:
	ocamlfind remove xs

include $(TOPLEVEL)/Makefile.rules

