OCAML_TOPLEVEL=$(CURDIR)/../..
XEN_ROOT=$(OCAML_TOPLEVEL)/../..
include $(OCAML_TOPLEVEL)/common.make

CFLAGS += -I../mmap $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest)
CFLAGS += $(APPEND_CFLAGS)
OCAMLINCLUDE += -I ../mmap -I ../eventchn

OBJS = xenctrl
INTF = xenctrl.cmi
LIBS = xenctrl.cma xenctrl.cmxa

LIBS_xenctrl = $(call xenlibs-ldflags-ldlibs,ctrl guest)

xenctrl_OBJS = $(OBJS)
xenctrl_C_OBJS = xenctrl_stubs

OCAML_LIBRARY = xenctrl

all: $(INTF) $(LIBS)

libs: $(LIBS)

.PHONY: install
install: $(LIBS) META
	mkdir -p $(OCAMLDESTDIR)
	$(OCAMLFIND) remove -destdir $(OCAMLDESTDIR) xenctrl
	$(OCAMLFIND) install -destdir $(OCAMLDESTDIR) -ldconf ignore xenctrl META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	$(OCAMLFIND) remove -destdir $(OCAMLDESTDIR) xenctrl

xenctrl_stubs.o: xenctrl_abi_check.h

xenctrl_abi_check.h: abi-check xenctrl_stubs.c xenctrl.ml
	$(PERL) -w $^ >$@.tmp && mv -f $@.tmp $@

GENERATED_FILES += xenctrl_abi_check.h

include $(OCAML_TOPLEVEL)/Makefile.rules
