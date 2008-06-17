XEN_ROOT = ../..

include $(XEN_ROOT)/Config.mk

CAMLLIB = $(shell ocamlc -where)
DEF_CPPFLAGS += -I$(CAMLLIB)

OCAMLFIND=ocamlfind
OCAMLOPT=ocamlopt

OBJS := hello.cmx
LIBS := 

all: main-caml.o caml.o

%.cmx: %.ml
	$(OCAMLFIND) $(OCAMLOPT) -c $< -o $@

caml.o: $(OBJS)
	$(OCAMLFIND) $(OCAMLOPT) $(LIBS) $^ -output-obj -o $@

clean:
	rm -f *.a *.o *.cmx *.cmi
