TOPLEVEL=$(CURDIR)/../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

CFLAGS += $(CFLAGS_libxenlight)

OBJS = xl
INTF = xl.cmi
LIBS = xl.cma xl.cmxa

LIBS_xl = $(LDLIBS_libxenlight)

xl_OBJS = $(OBJS)
xl_C_OBJS = xl_stubs

OCAML_LIBRARY = xl

all: $(INTF) $(LIBS)

libs: $(LIBS)

.PHONY: install
install: $(LIBS) META
	mkdir -p $(OCAMLDESTDIR)
	ocamlfind remove -destdir $(OCAMLDESTDIR) xl
	ocamlfind install -destdir $(OCAMLDESTDIR) -ldconf ignore xl META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	ocamlfind remove -destdir $(OCAMLDESTDIR) xl

include $(TOPLEVEL)/Makefile.rules
