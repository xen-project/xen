TOPLEVEL=$(CURDIR)/../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_xeninclude)

OBJS = xeneventchn
INTF = $(foreach obj, $(OBJS),$(obj).cmi)
LIBS = xeneventchn.cma xeneventchn.cmxa

LIBS_xeneventchn = $(LDLIBS_libxenctrl)

all: $(INTF) $(LIBS) $(PROGRAMS)

bins: $(PROGRAMS)

libs: $(LIBS)

xeneventchn_OBJS = $(OBJS)
xeneventchn_C_OBJS = xeneventchn_stubs

OCAML_LIBRARY = xeneventchn

.PHONY: install
install: $(LIBS) META
	mkdir -p $(OCAMLDESTDIR)
	ocamlfind remove -destdir $(OCAMLDESTDIR) xeneventchn
	ocamlfind install -destdir $(OCAMLDESTDIR) -ldconf ignore xeneventchn META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	ocamlfind remove -destdir $(OCAMLDESTDIR) xeneventchn

include $(TOPLEVEL)/Makefile.rules

