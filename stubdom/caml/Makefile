XEN_ROOT = ../..

include $(XEN_ROOT)/Config.mk

CAMLLIB = $(shell ocamlc -where)
DEF_CPPFLAGS += -I$(CAMLLIB)

OCAMLFIND=ocamlfind
OCAMLOPT=ocamlopt

OBJS := hello.cmx
LIBS := 

all: main-c.o main-caml.o caml.o

main-c.c:
	ln -sf $(XEN_ROOT)/extras/mini-os/main.c $@

%.cmx: %.ml
	$(OCAMLFIND) $(OCAMLOPT) -c $< -o $@

caml.o: $(OBJS)
	$(OCAMLFIND) $(OCAMLOPT) $(LIBS) $^ -output-obj -o $@

clean:
	rm -f *.a *.o *.cmx *.cmi
