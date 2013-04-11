XEN_ROOT = $(CURDIR)/../../..
OCAML_TOPLEVEL = $(CURDIR)/..
include $(OCAML_TOPLEVEL)/common.make

OCAMLINCLUDE += \
	-I $(OCAML_TOPLEVEL)/libs/xb \
	-I $(OCAML_TOPLEVEL)/libs/mmap \
	-I $(OCAML_TOPLEVEL)/libs/xc \
	-I $(OCAML_TOPLEVEL)/libs/eventchn

LIBS = syslog.cma syslog.cmxa
syslog_OBJS = syslog
syslog_C_OBJS = syslog_stubs
OCAML_LIBRARY = syslog

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

INTF = symbol.cmi trie.cmi syslog.cmi

XENSTOREDLIBS = \
	unix.cmxa \
	-ccopt -L -ccopt . syslog.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/mmap $(OCAML_TOPLEVEL)/libs/mmap/xenmmap.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/eventchn $(OCAML_TOPLEVEL)/libs/eventchn/xeneventchn.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/xc $(OCAML_TOPLEVEL)/libs/xc/xenctrl.cmxa \
	-ccopt -L -ccopt $(OCAML_TOPLEVEL)/libs/xb $(OCAML_TOPLEVEL)/libs/xb/xenbus.cmxa \
	-ccopt -L -ccopt $(XEN_ROOT)/tools/libxc

PROGRAMS = oxenstored

oxenstored_LIBS = $(XENSTOREDLIBS)
oxenstored_OBJS = $(OBJS)

OCAML_PROGRAM = oxenstored

all: $(INTF) $(LIBS) $(PROGRAMS)

bins: $(PROGRAMS)

libs: $(LIBS)

install: all
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) oxenstored $(DESTDIR)$(SBINDIR)
	$(INSTALL_DIR) $(DESTDIR)$(XEN_CONFIG_DIR)
	$(INSTALL_DATA) oxenstored.conf $(DESTDIR)$(XEN_CONFIG_DIR)

include $(OCAML_TOPLEVEL)/Makefile.rules
