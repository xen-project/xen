TOPLEVEL=$(CURDIR)/../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

CFLAGS += $(CFLAGS_libxenevtchn) $(CFLAGS_xeninclude)

OBJS = xeneventchn
INTF = $(foreach obj, $(OBJS),$(obj).cmi)
LIBS = xeneventchn.cma xeneventchn.cmxa

LIBS_xeneventchn = $(LDLIBS_libxenevtchn)

all: $(INTF) $(LIBS) $(PROGRAMS)

bins: $(PROGRAMS)

libs: $(LIBS)

xeneventchn_OBJS = $(OBJS)
xeneventchn_C_OBJS = xeneventchn_stubs

OCAML_LIBRARY = xeneventchn

.PHONY: install
install: $(LIBS) META
	mkdir -p $(OCAMLDESTDIR)
	$(OCAMLFIND) remove -destdir $(OCAMLDESTDIR) xeneventchn
	$(OCAMLFIND) install -destdir $(OCAMLDESTDIR) -ldconf ignore xeneventchn META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	$(OCAMLFIND) remove -destdir $(OCAMLDESTDIR) xeneventchn

include $(TOPLEVEL)/Makefile.rules

