XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS   += -Werror
CFLAGS   += -fno-strict-aliasing
CFLAGS   += -I. $(CFLAGS_libxenctrl)

CPPFLAGS += -MMD -MF .$*.d
PROG_DEPS = .*.d

XML2VERSION = $(shell xml2-config --version )
CFLAGS     += $(shell xml2-config --cflags )
CFLAGS     += $(shell if [[ $(XML2VERSION) < 2.6.20 ]]; then echo ""; else echo "-DVALIDATE_SCHEMA"; fi )
LDFLAGS    += $(shell xml2-config --libs ) # if this does not work, try -L/usr/lib -lxml2 -lz -lpthread -lm

SRCS_TOOL     = secpol_tool.c
OBJS_TOOL    := $(patsubst %.c,%.o,$(filter %.c,$(SRCS_TOOL)))

ACM_INST_TOOLS    = xensec_tool xensec_gen
ACM_EZPOLICY      = xensec_ezpolicy
ACM_OBJS          = $(OBJS_TOOL) $(OBJS_GETD)
ACM_SCRIPTS       = python/xensec_tools/acm_getlabel

ACM_CONFIG_DIR    = $(XEN_CONFIG_DIR)/acm-security
ACM_POLICY_DIR    = $(ACM_CONFIG_DIR)/policies
ACM_SCRIPT_DIR    = $(ACM_CONFIG_DIR)/scripts

ACM_INST_HTML     = python/xensec_gen/index.html
ACM_INST_CGI      = python/xensec_gen/cgi-bin/policy.cgi
ACM_SECGEN_HTMLDIR= /var/lib/xensec_gen
ACM_SECGEN_CGIDIR = $(ACM_SECGEN_HTMLDIR)/cgi-bin

ACM_SCHEMA        = security_policy.xsd
ACM_EXAMPLES      = client_v1 test
ACM_DEF_POLICIES  =
ACM_POLICY_SUFFIX = security_policy.xml

ifeq ($(ACM_SECURITY),y)
.PHONY: all
all: build

.PHONY: install
install: all $(ACM_CONFIG_FILE)
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) $(ACM_INST_TOOLS) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) $(ACM_EZPOLICY) $(DESTDIR)$(SBINDIR)
	$(INSTALL_DIR) $(DESTDIR)$(ACM_CONFIG_DIR)
	$(INSTALL_DIR) $(DESTDIR)$(ACM_POLICY_DIR)
	$(INSTALL_DATA) policies/$(ACM_SCHEMA) $(DESTDIR)$(ACM_POLICY_DIR)
	$(INSTALL_DIR) $(DESTDIR)$(ACM_POLICY_DIR)/example
	set -e; for i in $(ACM_EXAMPLES); do \
		$(INSTALL_DATA) policies/example/$$i-$(ACM_POLICY_SUFFIX) $(DESTDIR)$(ACM_POLICY_DIR)/example/; \
	done
	set -e; for i in $(ACM_DEF_POLICIES); do \
		$(INSTALL_DATA) policies/$$i-$(ACM_POLICY_SUFFIX) $(DESTDIR)$(ACM_POLICY_DIR); \
	done
	$(INSTALL_DIR) $(DESTDIR)$(ACM_SCRIPT_DIR)
	$(INSTALL_PROG) $(ACM_SCRIPTS) $(DESTDIR)$(ACM_SCRIPT_DIR)
	$(INSTALL_DIR) $(DESTDIR)$(ACM_SECGEN_HTMLDIR)
	$(INSTALL_DATA) $(ACM_INST_HTML) $(DESTDIR)$(ACM_SECGEN_HTMLDIR)
	$(INSTALL_DIR) $(DESTDIR)$(ACM_SECGEN_CGIDIR)
	$(INSTALL_PROG) $(ACM_INST_CGI) $(DESTDIR)$(ACM_SECGEN_CGIDIR)
	$(PYTHON) python/setup.py install $(PYTHON_PREFIX_ARG) \
		--root="$(DESTDIR)" --force
else
.PHONY: all
all:

.PHONY: install
install:
endif

.PHONY: build
build: $(ACM_INST_TOOLS) $(ACM_NOINST_TOOLS)
	$(PYTHON) python/setup.py build
	chmod 700 $(ACM_SCRIPTS)

xensec_tool: $(OBJS_TOOL)
	$(CC) -g $(CFLAGS) $(LDFLAGS) -O0 -o $@ $^ $(LDLIBS_libxenctrl)

xensec_gen: xensec_gen.py
	cp -f $^ $@

.PHONY: clean
clean:
	$(RM) $(ACM_INST_TOOLS) $(ACM_NOINST_TOOLS)
	$(RM) $(ACM_OBJS)
	$(RM) $(PROG_DEPS)
	$(RM) -r build

.PHONY: mrproper
mrproper: clean

-include $(PROG_DEPS)
