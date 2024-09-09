OCAML_TOPLEVEL=$(CURDIR)/../../..
XEN_ROOT=$(OCAML_TOPLEVEL)/../..
include $(OCAML_TOPLEVEL)/common.make

CFLAGS += -I $(OCAML_TOPLEVEL)/libs -I $(OCAML_TOPLEVEL)/libs/xsd_glue
CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_xeninclude) $(APPEND_CFLAGS)
OCAMLOPTFLAGS += -opaque
OCAMLINCLUDE += -I ./ -I ../

OBJS = domain_getinfo_v1
INTF = $(foreach obj, $(OBJS),$(obj).cmi)
LIBS = domain_getinfo_v1.cmxa domain_getinfo_v1.cmxs

LIBS_xsd_glue = $(call xenlibs-ldflags-ldlibs,xenctrl)

all: $(INTF) $(LIBS) $(PROGRAMS)

bins: $(PROGRAMS)

libs: $(LIBS)

domain_getinfo_v1_OBJS = $(OBJS)
domain_getinfo_v1 = $(OBJS)
domain_getinfo_v1_C_OBJS = domain_getinfo_stubs_v1

OCAML_DYN_LIBRARY = domain_getinfo_v1

.PHONY: install
install: $(LIBS) META
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC)/ocaml/xsd_glue/xenctrl_plugin
	$(INSTALL_PROG) domain_getinfo_v1.cmxs $(DESTDIR)$(LIBEXEC)/ocaml/xsd_glue/xenctrl_plugin

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(LIBEXEC)/ocaml/xsd_glue/xenctrl_plugin/domain_getinfo_v1.cmxs

include $(OCAML_TOPLEVEL)/Makefile.rules
