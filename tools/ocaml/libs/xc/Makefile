TOPLEVEL=$(CURDIR)/../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

CFLAGS += -I../mmap -I./ -I$(XEN_ROOT)/tools/libxc
OCAMLINCLUDE += -I ../mmap -I ../uuid -I $(XEN_ROOT)/tools/libxc

OBJS = xc
INTF = xc.cmi
LIBS = xc.cma xc.cmxa

LIBS_xc = -L$(XEN_ROOT)/tools/libxc -lxenctrl -lxenguest

xc_OBJS = $(OBJS)
xc_C_OBJS = xc_stubs

OCAML_LIBRARY = xc

all: $(INTF) $(LIBS)

libs: $(LIBS)

.PHONY: install
install: $(LIBS) META
	mkdir -p $(OCAMLDESTDIR)
	ocamlfind remove -destdir $(OCAMLDESTDIR) xc
	ocamlfind install -destdir $(OCAMLDESTDIR) -ldconf ignore xc META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	ocamlfind remove -destdir $(OCAMLDESTDIR) xc

include $(TOPLEVEL)/Makefile.rules
