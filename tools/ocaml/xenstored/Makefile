XEN_ROOT = $(CURDIR)/../../..
OCAML_TOPLEVEL = $(CURDIR)/..
include $(OCAML_TOPLEVEL)/common.make

# Include configure output (config.h)
CFLAGS += -include $(XEN_ROOT)/tools/config.h
CFLAGS-$(CONFIG_SYSTEMD)  += $(SYSTEMD_CFLAGS)
LDFLAGS-$(CONFIG_SYSTEMD) += $(SYSTEMD_LIBS)

CFLAGS  += $(CFLAGS-y)
CFLAGS  += $(APPEND_CFLAGS)
LDFLAGS += $(LDFLAGS-y)
LDFLAGS += $(APPEND_LDFLAGS)

OCAMLINCLUDE += \
	-I $(OCAML_TOPLEVEL)/libs/xb \
	-I $(OCAML_TOPLEVEL)/libs/mmap \
	-I $(OCAML_TOPLEVEL)/libs/xc \
	-I $(OCAML_TOPLEVEL)/libs/eventchn

LIBS = syslog.cma syslog.cmxa select.cma select.cmxa
syslog_OBJS = syslog
syslog_C_OBJS = syslog_stubs
select_OBJS = select
select_C_OBJS = select_stubs
OCAML_LIBRARY = syslog select

LIBS += systemd.cma systemd.cmxa
systemd_OBJS = systemd
systemd_C_OBJS = systemd_stubs
OCAML_LIBRARY += systemd

LIBS_systemd += $(LDFLAGS-y)

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

INTF = symbol.cmi trie.cmi syslog.cmi systemd.cmi select.cmi

XENSTOREDLIBS = \
	unix.cmxa \
	-ccopt -L -ccopt . syslog.cmxa \
	-ccopt -L -ccopt . systemd.cmxa \
	-ccopt -L -ccopt . select.cmxa \
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
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) oxenstored $(DESTDIR)$(sbindir)
	$(INSTALL_DIR) $(DESTDIR)$(XEN_CONFIG_DIR)
	$(INSTALL_DATA) oxenstored.conf $(DESTDIR)$(XEN_CONFIG_DIR)

include $(OCAML_TOPLEVEL)/Makefile.rules
