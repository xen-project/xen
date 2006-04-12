XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS   += -Werror
CFLAGS   += -fno-strict-aliasing
CFLAGS   += -I.

CPPFLAGS += -MMD -MF .$*.d
PROG_DEPS = .*.d

XML2VERSION = $(shell xml2-config --version )
CFLAGS     += $(shell xml2-config --cflags )
CFLAGS     += $(shell if [[ $(XML2VERSION) < 2.6.20 ]]; then echo ""; else echo "-DVALIDATE_SCHEMA"; fi )
LDFLAGS    += $(shell xml2-config --libs ) # if this does not work, try -L/usr/lib -lxml2 -lz -lpthread -lm

ifeq ($(ACM_DEFAULT_SECURITY_POLICY),ACM_NULL_POLICY)
POLICY=null
endif
ifeq ($(ACM_DEFAULT_SECURITY_POLICY),ACM_CHINESE_WALL_POLICY)
POLICY=chwall
endif
ifeq ($(ACM_DEFAULT_SECURITY_POLICY),ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY)
POLICY=ste
endif
ifeq ($(ACM_DEFAULT_SECURITY_POLICY),ACM_CHINESE_WALL_AND_SIMPLE_TYPE_ENFORCEMENT_POLICY)
POLICY=chwall_ste
endif

SRCS_TOOL     = secpol_tool.c
OBJS_TOOL    := $(patsubst %.c,%.o,$(filter %.c,$(SRCS_TOOL)))
SRCS_XML2BIN  = secpol_xml2bin.c secpol_xml2bin.h
OBJS_XML2BIN := $(patsubst %.c,%.o,$(filter %.c,$(SRCS_XML2BIN)))
SRCS_GETD     = get_decision.c
OBJS_GETD    := $(patsubst %.c,%.o,$(filter %.c,$(SRCS_GETD)))

ACM_INST_TOOLS    = xensec_tool xensec_xml2bin xensec_gen
ACM_NOINST_TOOLS  = get_decision
ACM_OBJS          = $(OBJS_TOOL) $(OBJS_XML2BIN) $(OBJS_GETD)
ACM_SCRIPTS       = getlabel.sh setlabel.sh updategrub.sh labelfuncs.sh

ACM_CONFIG_DIR    = /etc/xen/acm-security
ACM_POLICY_DIR    = $(ACM_CONFIG_DIR)/policies
ACM_SCRIPT_DIR    = $(ACM_CONFIG_DIR)/scripts

ACM_INST_HTML     = python/xensec_gen/index.html
ACM_INST_CGI      = python/xensec_gen/cgi-bin/policy.cgi \
                    python/xensec_gen/cgi-bin/policylabel.cgi
ACM_SECGEN_HTMLDIR= /var/lib/xensec_gen
ACM_SECGEN_CGIDIR = $(ACM_SECGEN_HTMLDIR)/cgi-bin

ACM_SCHEMA        = security_policy.xsd
ACM_EXAMPLES      = null chwall ste chwall_ste
ACM_POLICY_SUFFIX = security_policy.xml
ACM_LABEL_SUFFIX  = security_label_template.xml

ifeq ($(ACM_SECURITY),y)
.PHONY: all
all: build

.PHONY: install
install: all $(ACM_CONFIG_FILE)
	$(INSTALL_DIR) -p $(DESTDIR)/usr/sbin
	$(INSTALL_PROG) -p $(ACM_INST_TOOLS) $(DESTDIR)/usr/sbin
	$(INSTALL_DIR) -p $(DESTDIR)$(ACM_CONFIG_DIR)
	$(INSTALL_DIR) -p $(DESTDIR)$(ACM_POLICY_DIR)
	$(INSTALL_DATA) -p policies/$(ACM_SCHEMA) $(DESTDIR)$(ACM_POLICY_DIR)
	for i in $(ACM_EXAMPLES); do \
		$(INSTALL_DIR) -p $(DESTDIR)$(ACM_POLICY_DIR)/$$i; \
		$(INSTALL_DATA) -p policies/$$i/$$i-$(ACM_POLICY_SUFFIX) $(DESTDIR)$(ACM_POLICY_DIR)/$$i; \
		$(INSTALL_DATA) -p policies/$$i/$$i-$(ACM_LABEL_SUFFIX) $(DESTDIR)$(ACM_POLICY_DIR)/$$i; \
	done
	$(INSTALL_DIR) -p $(DESTDIR)$(ACM_SCRIPT_DIR)
	$(INSTALL_PROG) -p $(ACM_SCRIPTS) $(DESTDIR)$(ACM_SCRIPT_DIR)
	$(INSTALL_DIR) -p $(DESTDIR)$(ACM_SECGEN_HTMLDIR)
	$(INSTALL_DATA) -p $(ACM_INST_HTML) $(DESTDIR)$(ACM_SECGEN_HTMLDIR)
	$(INSTALL_DIR) -p $(DESTDIR)$(ACM_SECGEN_CGIDIR)
	$(INSTALL_PROG) -p $(ACM_INST_CGI) $(DESTDIR)$(ACM_SECGEN_CGIDIR)
ifndef XEN_PYTHON_NATIVE_INSTALL
	python python/setup.py install --home="$(DESTDIR)/usr"
else
	python python/setup.py install --root="$(DESTDIR)"
endif
else
.PHONY: all
all:

.PHONY: install
install:
endif

.PHONY: build
build: mk-symlinks $(ACM_INST_TOOLS) $(ACM_NOINST_TOOLS)
	python python/setup.py build
	chmod 700 $(ACM_SCRIPTS)

xensec_tool: $(OBJS_TOOL)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

xensec_xml2bin: $(OBJS_XML2BIN)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

get_decision: $(OBJS_GETD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

xensec_gen: xensec_gen.py
	cp -f $^ $@

.PHONY: clean
clean:
	$(RM) $(ACM_INST_TOOLS) $(ACM_NOINST_TOOLS)
	$(RM) $(ACM_OBJS)
	$(RM) $(PROG_DEPS)
	$(RM) -r xen
	$(RM) -r build

.PHONY: mrproper
mrproper: clean

.PHONY: boot_install
boot_install: install
	$(ACM_SCRIPT_DIR)/updategrub.sh $(POLICY) $(KERNEL_VERSION)

-include $(PROG_DEPS)
