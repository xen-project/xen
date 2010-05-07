XEN_ROOT = ../../..
OCAML_TOPLEVEL = ..
include $(OCAML_TOPLEVEL)/common.make

OCAMLINCLUDE += \
	-I $(OCAML_TOPLEVEL)/libs/log \
	-I $(OCAML_TOPLEVEL)/libs/xb \
	-I $(OCAML_TOPLEVEL)/libs/uuid \
	-I $(OCAML_TOPLEVEL)/libs/mmap \
	-I $(OCAML_TOPLEVEL)/libs/xc \
	-I $(OCAML_TOPLEVEL)/libs/eventchn

OBJS = define \
	stdext \
	trie \
	config \
	logging \
	quota \
	perms \
	symbol \
	utils \
	store \
	disk \
	transaction \
	event \
	domain \
	domains \
	connection \
	connections \
	parse_arg \
	process \
	xenstored

INTF = symbol.cmi trie.cmi
XENSTOREDLIBS = \
	unix.cmxa \
	$(OCAML_TOPLEVEL)/libs/uuid/uuid.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/mmap $(OCAML_TOPLEVEL)/libs/mmap/mmap.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/log $(OCAML_TOPLEVEL)/libs/log/log.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/eventchn $(OCAML_TOPLEVEL)/libs/eventchn/eventchn.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/xc $(OCAML_TOPLEVEL)/libs/xc/xc.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/xb $(OCAML_TOPLEVEL)/libs/xb/xb.cmxa

PROGRAMS = oxenstored

oxenstored_LIBS = $(XENSTOREDLIBS)
oxenstored_OBJS = $(OBJS)

OCAML_PROGRAM = oxenstored

all: $(INTF) $(PROGRAMS)

bins: $(PROGRAMS)

include $(OCAML_TOPLEVEL)/Makefile.rules
