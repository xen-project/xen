#
# Makefile for the security policy.
#
# Targets:
# 
# install       - compile and install the policy configuration, and context files.
# load          - compile, install, and load the policy configuration.
# reload        - compile, install, and load/reload the policy configuration.
# policy        - compile the policy configuration locally for testing/development.
#
# The default target is 'policy'.
#

########################################
#
# Configurable portions of the Makefile
#

# Policy version
# By default, checkpolicy will create the highest
# version policy it supports.  Setting this will
# override the version.
#OUTPUT_POLICY = 20

# Policy Type
# strict, targeted,
# strict-mls, targeted-mls,
# strict-mcs, targeted-mcs
TYPE = strict

# Policy Name
# If set, this will be used as the policy
# name.  Otherwise the policy type will be
# used for the name.
NAME = xenrefpolicy

# Distribution
# Some distributions have portions of policy
# for programs or configurations specific to the
# distribution.  Setting this will enable options
# for the distribution.
# redhat, gentoo, debian, and suse are current options.
# Fedora users should enable redhat.
#DISTRO = 

# Build monolithic policy.  Putting n here
# will build a loadable module policy.
MONOLITHIC=y

# Uncomment this to disable command echoing
#QUIET:=@

########################################
#
# NO OPTIONS BELOW HERE
#

# executable paths
PREFIX := /usr
BINDIR := $(PREFIX)/bin
SBINDIR := $(PREFIX)/sbin
CHECKPOLICY := $(BINDIR)/checkpolicy
CHECKMODULE := $(BINDIR)/checkmodule
SEMOD_PKG := $(BINDIR)/semodule_package
LOADPOLICY := $(SBINDIR)/flask-loadpolicy

CFLAGS := -Wall

# policy source layout
POLDIR := policy
MODDIR := $(POLDIR)/modules
FLASKDIR := $(POLDIR)/flask
SECCLASS := $(FLASKDIR)/security_classes
ISIDS := $(FLASKDIR)/initial_sids
AVS := $(FLASKDIR)/access_vectors

#policy building support tools
SUPPORT := support
FCSORT := tmp/fc_sort

# config file paths
GLOBALTUN := $(POLDIR)/global_tunables
GLOBALBOOL := $(POLDIR)/global_booleans
MOD_CONF := $(POLDIR)/modules.conf
TUNABLES := $(POLDIR)/tunables.conf
BOOLEANS := $(POLDIR)/booleans.conf

# install paths
TOPDIR = $(DESTDIR)$(XEN_CONFIG_DIR)
INSTALLDIR = $(TOPDIR)/$(NAME)
SRCPATH = $(INSTALLDIR)/src
USERPATH = $(INSTALLDIR)/users
CONTEXTPATH = $(INSTALLDIR)/contexts

# enable MLS if requested.
ifneq ($(findstring -mls,$(TYPE)),)
	override M4PARAM += -D enable_mls
	CHECKPOLICY += -M
	CHECKMODULE += -M
endif

# enable MLS if MCS requested.
ifneq ($(findstring -mcs,$(TYPE)),)
	override M4PARAM += -D enable_mcs
	CHECKPOLICY += -M
	CHECKMODULE += -M
endif

# compile targeted policy if requested.
ifneq ($(findstring targeted,$(TYPE)),)
	override M4PARAM += -D targeted_policy
endif

# enable distribution-specific policy
ifneq ($(DISTRO),)
	override M4PARAM += -D distro_$(DISTRO)
endif

ifneq ($(OUTPUT_POLICY),)
	CHECKPOLICY += -c $(OUTPUT_POLICY)
endif

ifeq ($(NAME),)
	NAME := $(TYPE)
endif

# determine the policy version and current kernel version if possible
PV := $(shell $(CHECKPOLICY) -V |cut -f 1 -d ' ')
KV := $(shell cat /selinux/policyvers)

# dont print version warnings if we are unable to determine
# the currently running kernel's policy version
ifeq ($(KV),)
	KV := $(PV)
endif

FC := file_contexts
POLVER := policy.$(PV)

M4SUPPORT = $(wildcard $(POLDIR)/support/*.spt)

APPCONF := config/appconfig-$(TYPE)
APPDIR := $(CONTEXTPATH)
APPFILES := $(INSTALLDIR)/booleans
CONTEXTFILES += $(wildcard $(APPCONF)/*_context*) $(APPCONF)/media
USER_FILES := $(POLDIR)/systemuser $(POLDIR)/users

ALL_LAYERS := $(filter-out $(MODDIR)/CVS,$(shell find $(wildcard $(MODDIR)/*) -maxdepth 0 -type d))

GENERATED_TE := $(basename $(foreach dir,$(ALL_LAYERS),$(wildcard $(dir)/*.te.in)))
GENERATED_IF := $(basename $(foreach dir,$(ALL_LAYERS),$(wildcard $(dir)/*.if.in)))
GENERATED_FC := $(basename $(foreach dir,$(ALL_LAYERS),$(wildcard $(dir)/*.fc.in)))

# sort here since it removes duplicates, which can happen
# when a generated file is already generated
DETECTED_MODS := $(sort $(foreach dir,$(ALL_LAYERS),$(wildcard $(dir)/*.te)) $(GENERATED_TE))

# modules.conf setting for base module
MODBASE := base

# modules.conf setting for module
MODMOD := module

# extract settings from modules.conf
BASE_MODS := $(foreach mod,$(shell awk '/^[[:blank:]]*[[:alpha:]]/{ if ($$3 == "$(MODBASE)") print $$1 }' $(MOD_CONF) 2> /dev/null),$(subst ./,,$(shell find -iname $(mod).te)))
MOD_MODS := $(foreach mod,$(shell awk '/^[[:blank:]]*[[:alpha:]]/{ if ($$3 == "$(MODMOD)") print $$1 }' $(MOD_CONF) 2> /dev/null),$(subst ./,,$(shell find -iname $(mod).te)))

HOMEDIR_TEMPLATE = tmp/homedir_template

########################################
#
# Load appropriate rules
#

ifeq ($(MONOLITHIC),y)
	include Rules.monolithic
else
	include Rules.modular
endif

########################################
#
# Create config files
#
conf: $(MOD_CONF) $(BOOLEANS) $(GENERATED_TE) $(GENERATED_IF) $(GENERATED_FC)

$(MOD_CONF) $(BOOLEANS): $(POLXML)
	@echo "Updating $(MOD_CONF) and $(BOOLEANS)"
	$(QUIET) cd $(DOCS) && ../$(GENDOC) -t ../$(BOOLEANS) -m ../$(MOD_CONF) -x ../$(POLXML)

########################################
#
# Appconfig files
#
install-appconfig: $(APPFILES)

$(INSTALLDIR)/booleans: $(BOOLEANS)
	@mkdir -p $(INSTALLDIR)
	$(QUIET) egrep '^[[:blank:]]*[[:alpha:]]' $(BOOLEANS) \
		| sed -e 's/false/0/g' -e 's/true/1/g' > tmp/booleans
	$(QUIET) install -m 644 tmp/booleans $@

########################################
#
# Install policy sources
#
install-src:
	rm -rf $(SRCPATH)/policy.old
	-mv $(SRCPATH)/policy $(SRCPATH)/policy.old
	mkdir -p $(SRCPATH)/policy
	cp -R . $(SRCPATH)/policy

########################################
#
# Clean everything
#
bare: clean
	rm -f $(POLXML)
	rm -f $(SUPPORT)/*.pyc
	rm -f $(FCSORT)
	rm -f $(MOD_CONF)
	rm -f $(BOOLEANS)
	rm -fR $(HTMLDIR)
ifneq ($(GENERATED_TE),)
	rm -f $(GENERATED_TE)
endif
ifneq ($(GENERATED_IF),)
	rm -f $(GENERATED_IF)
endif
ifneq ($(GENERATED_FC),)
	rm -f $(GENERATED_FC)
endif

.PHONY: install-src install-appconfig conf html bare
