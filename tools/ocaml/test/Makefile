XEN_ROOT = $(CURDIR)/../../..
OCAML_TOPLEVEL = $(CURDIR)/..
include $(OCAML_TOPLEVEL)/common.make

OCAMLINCLUDE += \
	-I $(OCAML_TOPLEVEL)/libs/xentoollog

OBJS = xtl

PROGRAMS = xtl

xtl_LIBS =  \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/xentoollog $(OCAML_TOPLEVEL)/libs/xentoollog/xentoollog.cmxa \
	-cclib $(LDLIBS_libxenctrl)

xtl_OBJS = xtl

OCAML_PROGRAM = xtl

all: $(PROGRAMS)

bins: $(PROGRAMS)

install: all
	$(INSTALL_DIR) $(DESTDIR)$(BINDIR)
	$(INSTALL_PROG) $(PROGRAMS) $(DESTDIR)$(BINDIR)

include $(OCAML_TOPLEVEL)/Makefile.rules
