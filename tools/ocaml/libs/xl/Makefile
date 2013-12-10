TOPLEVEL=$(CURDIR)/../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

# ignore unused generated functions and allow mixed declarations and code
CFLAGS += -Wno-unused -Wno-declaration-after-statement

CFLAGS += $(CFLAGS_libxenlight)
CFLAGS += -I ../xentoollog

OBJS = xenlight
INTF = xenlight.cmi
LIBS = xenlight.cma xenlight.cmxa

OCAMLINCLUDE += -I ../xentoollog

LIBS_xenlight = $(LDLIBS_libxenlight)

xenlight_OBJS = $(OBJS)
xenlight_C_OBJS = xenlight_stubs

OCAML_LIBRARY = xenlight

GENERATED_FILES += xenlight.ml xenlight.ml.tmp xenlight.mli xenlight.mli.tmp
GENERATED_FILES += _libxl_types.ml.in _libxl_types.mli.in
GENERATED_FILES += _libxl_types.inc META

all: $(INTF) $(LIBS)

xenlight.ml: xenlight.ml.in _libxl_types.ml.in
	$(Q)sed -e '1i\
(*\
 * AUTO-GENERATED FILE DO NOT EDIT\
 * Generated from xenlight.ml.in and _libxl_types.ml.in\
 *)\
' \
	    -e '/^(\* @@LIBXL_TYPES@@ \*)$$/r_libxl_types.ml.in' \
	  < xenlight.ml.in > xenlight.ml.tmp
	$(Q)mv xenlight.ml.tmp xenlight.ml

xenlight.mli: xenlight.mli.in _libxl_types.mli.in
	$(Q)sed -e '1i\
(*\
 * AUTO-GENERATED FILE DO NOT EDIT\
 * Generated from xenlight.mli.in and _libxl_types.mli.in\
 *)\
' \
	    -e '/^(\* @@LIBXL_TYPES@@ \*)$$/r_libxl_types.mli.in' \
	  < xenlight.mli.in > xenlight.mli.tmp
	$(Q)mv xenlight.mli.tmp xenlight.mli

_libxl_types.ml.in _libxl_types.mli.in _libxl_types.inc: genwrap.py $(XEN_ROOT)/tools/libxl/libxl_types.idl \
                $(XEN_ROOT)/tools/libxl/idl.py
	PYTHONPATH=$(XEN_ROOT)/tools/libxl $(PYTHON) genwrap.py \
		$(XEN_ROOT)/tools/libxl/libxl_types.idl \
		_libxl_types.mli.in _libxl_types.ml.in _libxl_types.inc

libs: $(LIBS)

.PHONY: install
install: $(LIBS) META
	mkdir -p $(OCAMLDESTDIR)
	$(OCAMLFIND) remove -destdir $(OCAMLDESTDIR) xenlight
	$(OCAMLFIND) install -destdir $(OCAMLDESTDIR) -ldconf ignore xenlight META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	$(OCAMLFIND) remove -destdir $(OCAMLDESTDIR) xenlight

include $(TOPLEVEL)/Makefile.rules
