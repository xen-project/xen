OCAML_TOPLEVEL=$(CURDIR)/../..
XEN_ROOT=$(OCAML_TOPLEVEL)/../..
include $(OCAML_TOPLEVEL)/common.make

SUBDIRS= domain_getinfo_plugin_v1

CFLAGS += $(CFLAGS_xeninclude)
OCAMLCFLAGS += -opaque
OCAMLOPTFLAGS += -opaque

OBJS = plugin_interface_v1
INTF = $(foreach obj, $(OBJS),$(obj).cmi)
LIBS = plugin_interface_v1.cma plugin_interface_v1.cmxa
LIBS_plugin_interface_v1 =
plugin_interface_v1_OBJS=$(OBJS)

.PHONY: all
all: $(INTF) $(LIBS) $(PROGRAMS) subdirs-all

bins: $(PROGRAMS)

libs: $(LIBS)

plugin_interface_v1 = $(OBJS)

OCAML_NOC_LIBRARY = plugin_interface_v1

.PHONY: install
install: $(LIBS) META subdirs-install
	mkdir -p $(OCAMLDESTDIR)
	$(OCAMLFIND) remove -destdir $(OCAMLDESTDIR) xsd_glue
	$(OCAMLFIND) install -destdir $(OCAMLDESTDIR) -ldconf ignore xsd_glue META $(INTF) $(LIBS) *.a

.PHONY: uninstall
uninstall: subdirs-uninstall
	$(OCAMLFIND) remove -destdir $(OCAMLDESTDIR) xsd_glue

.PHONY: clean
clean: subdirs-clean

.PHONY: distclean
distclean: subdirs-distclean

include $(OCAML_TOPLEVEL)/Makefile.rules
