TOPLEVEL=$(CURDIR)/../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

CFLAGS += -I../mmap
CFLAGS += $(CFLAGS_libxenctrl) # For xen_mb()
CFLAGS += $(CFLAGS_xeninclude)
OCAMLINCLUDE += -I ../mmap
OCAMLOPTFLAGS += -for-pack Xenbus

.NOTPARALLEL:
# Ocaml is such a PITA!

PREINTF = op.cmi partial.cmi packet.cmi
PREOBJS = op partial packet xs_ring
PRELIBS = $(foreach obj, $(PREOBJS),$(obj).cmo) $(foreach obj,$(PREOJBS),$(obj).cmx)
OBJS = op partial packet xs_ring xb
INTF = op.cmi packet.cmi xb.cmi
LIBS = xenbus.cma xenbus.cmxa

ALL_OCAML_OBJS = $(OBJS) $(PREOJBS)

all: $(PREINTF) $(PRELIBS) $(INTF) $(LIBS) $(PROGRAMS)

bins: $(PROGRAMS)

libs: $(LIBS)

xenbus_OBJS = xenbus
xenbus_C_OBJS = xs_ring_stubs xenbus_stubs
OCAML_LIBRARY = xenbus

xenbus.cmx : $(foreach obj, $(OBJS), $(obj).cmx)
	$(E) " CMX      $@"
	$(OCAMLOPT) -pack -o $@ $^

xenbus.cmo : $(foreach obj, $(OBJS), $(obj).cmo)
	$(E) " CMO      $@"
	$(OCAMLC) -pack -o $@ $^

%.mli: %.ml
	$(E) " MLI      $@"
	$(Q)$(OCAMLC) $(OCAMLINCLUDE) -i $< $o

.PHONY: install
install: $(LIBS) META
	mkdir -p $(OCAMLDESTDIR)
	$(OCAMLFIND) remove -destdir $(OCAMLDESTDIR) xenbus
	$(OCAMLFIND) install -destdir $(OCAMLDESTDIR) -ldconf ignore xenbus META $(LIBS) xenbus.cmo xenbus.cmi xenbus.cmx *.a *.so

.PHONY: uninstall
uninstall:
	$(OCAMLFIND) remove -destdir $(OCAMLDESTDIR) xenbus

include $(TOPLEVEL)/Makefile.rules
