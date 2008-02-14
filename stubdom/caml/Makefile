XEN_ROOT = ../..

include $(XEN_ROOT)/Config.mk

OCAMLFIND=ocamlfind
OCAMLOPT=ocamlopt

OBJS := hello.cmx
LIBS := 

%.cmx: %.ml
	$(OCAMLFIND) $(OCAMLOPT) -c $< -o $@

caml.o: $(OBJS)
	$(OCAMLFIND) $(OCAMLOPT) $(LIBS) $^ -output-obj -o $@

clean:
	rm -f *.o *.cmx *.cmi
