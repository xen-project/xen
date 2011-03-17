TOPLEVEL=$(CURDIR)/../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

OBJS = mmap
INTF = $(foreach obj, $(OBJS),$(obj).cmi)
LIBS = mmap.cma mmap.cmxa

all: $(INTF) $(LIBS) $(PROGRAMS)

bins: $(PROGRAMS)

libs: $(LIBS)

mmap_OBJS = $(OBJS)
mmap_C_OBJS = mmap_stubs
OCAML_LIBRARY = mmap

.PHONY: install
install: $(LIBS) META
	mkdir -p $(OCAMLDESTDIR)
	ocamlfind remove -destdir $(OCAMLDESTDIR) mmap
	ocamlfind install -destdir $(OCAMLDESTDIR) -ldconf ignore mmap META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	ocamlfind remove -destdir $(OCAMLDESTDIR) mmap

include $(TOPLEVEL)/Makefile.rules

