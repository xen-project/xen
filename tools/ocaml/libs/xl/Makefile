TOPLEVEL=../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

OBJS = xl
INTF = xl.cmi
LIBS = xl.cma xl.cmxa

xl_OBJS = $(OBJS)
xl_C_OBJS = xl_stubs

OCAML_LIBRARY = xl

all: $(INTF) $(LIBS)

libs: $(LIBS)

.PHONY: install
install: $(LIBS) META
	ocamlfind install -destdir $(DESTDIR)$(shell ocamlfind printconf destdir) -ldconf ignore xl META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	ocamlfind remove xl

include $(TOPLEVEL)/Makefile.rules
