TOPLEVEL=../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

CFLAGS += -I../mmap -I./
OCAMLINCLUDE += -I ../mmap -I ../uuid

OBJS = xc
INTF = xc.cmi
LIBS = xc.cma xc.cmxa

xc_OBJS = $(OBJS)
xc_C_OBJS = xc_lib xc_stubs

OCAML_LIBRARY = xc

all: $(INTF) $(LIBS)

libs: $(LIBS)

.PHONY: install
install: $(LIBS) META
	ocamlfind install -destdir $(DESTDIR)$(shell ocamlfind printconf destdir) -ldconf ignore xc META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	ocamlfind remove xc

include $(TOPLEVEL)/Makefile.rules
