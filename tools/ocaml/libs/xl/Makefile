TOPLEVEL=$(CURDIR)/../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

# ignore unused generated functions
CFLAGS += -Wno-unused
CFLAGS += $(CFLAGS_libxenlight)

OBJS = xl
INTF = xl.cmi
LIBS = xl.cma xl.cmxa

LIBS_xl = $(LDLIBS_libxenlight)

xl_OBJS = $(OBJS)
xl_C_OBJS = xl_stubs

OCAML_LIBRARY = xl

GENERATED_FILES += xl.ml xl.ml.tmp xl.mli xl.mli.tmp
GENERATED_FILES += _libxl_types.ml.in _libxl_types.mli.in
GENERATED_FILES += _libxl_types.inc

all: $(INTF) $(LIBS)

xl.ml: xl.ml.in _libxl_types.ml.in
	$(Q)sed -e '1i\
(*\
 * AUTO-GENERATED FILE DO NOT EDIT\
 * Generated from xl.ml.in and _libxl_types.ml.in\
 *)\
' \
	    -e '/^(\* @@LIBXL_TYPES@@ \*)$$/r_libxl_types.ml.in' \
	  < xl.ml.in > xl.ml.tmp
	$(Q)mv xl.ml.tmp xl.ml

xl.mli: xl.mli.in _libxl_types.mli.in
	$(Q)sed -e '1i\
(*\
 * AUTO-GENERATED FILE DO NOT EDIT\
 * Generated from xl.mli.in and _libxl_types.mli.in\
 *)\
' \
	    -e '/^(\* @@LIBXL_TYPES@@ \*)$$/r_libxl_types.mli.in' \
	  < xl.mli.in > xl.mli.tmp
	$(Q)mv xl.mli.tmp xl.mli

_libxl_types.ml.in _libxl_types.mli.in _libxl_types.inc: genwrap.py $(XEN_ROOT)/tools/libxl/libxl.idl \
                $(XEN_ROOT)/tools/libxl/libxltypes.py
	PYTHONPATH=$(XEN_ROOT)/tools/libxl $(PYTHON) genwrap.py \
		$(XEN_ROOT)/tools/libxl/libxl.idl \
		_libxl_types.mli.in _libxl_types.ml.in _libxl_types.inc

libs: $(LIBS)

.PHONY: install
install: $(LIBS) META
	mkdir -p $(OCAMLDESTDIR)
	ocamlfind remove -destdir $(OCAMLDESTDIR) xl
	ocamlfind install -destdir $(OCAMLDESTDIR) -ldconf ignore xl META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	ocamlfind remove -destdir $(OCAMLDESTDIR) xl

include $(TOPLEVEL)/Makefile.rules
