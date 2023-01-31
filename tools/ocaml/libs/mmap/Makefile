OCAML_TOPLEVEL=$(CURDIR)/../..
XEN_ROOT=$(OCAML_TOPLEVEL)/../..
include $(OCAML_TOPLEVEL)/common.make

CFLAGS += $(CFLAGS_xeninclude)

OBJS = xenmmap
INTF = $(foreach obj, $(OBJS),$(obj).cmi)
LIBS = xenmmap.cma xenmmap.cmxa

all: $(INTF) $(LIBS) $(PROGRAMS)

bins: $(PROGRAMS)

libs: $(LIBS)

xenmmap_OBJS = $(OBJS)
xenmmap_C_OBJS = xenmmap_stubs
OCAML_LIBRARY = xenmmap

.PHONY: install
install: $(LIBS) META
	mkdir -p $(OCAMLDESTDIR)
	$(OCAMLFIND) remove -destdir $(OCAMLDESTDIR) xenmmap
	$(OCAMLFIND) install -destdir $(OCAMLDESTDIR) -ldconf ignore xenmmap META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	$(OCAMLFIND) remove -destdir $(OCAMLDESTDIR) xenmmap

include $(OCAML_TOPLEVEL)/Makefile.rules

