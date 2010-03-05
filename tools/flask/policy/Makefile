#
# Makefile for the security policy.
#
# Targets:
# 
# install       - compile and install the policy configuration.
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
# OUTPUT_POLICY = 24

# Policy Type
# xen
# xen-mls
TYPE = xen 

# Policy Name
# If set, this will be used as the policy
# name.  Otherwise xenpolicy will be
# used for the name.
# NAME = xenpolicy

# Number of MLS Sensitivities
# The sensitivities will be s0 to s(MLS_SENS-1).
# Dominance will be in increasing numerical order
# with s0 being lowest.
# MLS_SENS = 16

# Number of MLS Categories
# The categories will be c0 to c(MLS_CATS-1).
# MLS_CATS = 256

# Uncomment this to disable command echoing
# QUIET:=@

########################################
#
# NO OPTIONS BELOW HERE
#

# executable paths
PREFIX := /usr
BINDIR := $(PREFIX)/bin
SBINDIR := $(PREFIX)/sbin
CHECKPOLICY := $(BINDIR)/checkpolicy
LOADPOLICY := $(SBINDIR)/flask-loadpolicy

# policy source layout
POLDIR := policy
MODDIR := $(POLDIR)/modules
FLASKDIR := $(POLDIR)/flask
SECCLASS := $(FLASKDIR)/security_classes
ISIDS := $(FLASKDIR)/initial_sids
AVS := $(FLASKDIR)/access_vectors

# config file paths
GLOBALTUN := $(POLDIR)/global_tunables
GLOBALBOOL := $(POLDIR)/global_booleans
MOD_CONF := $(POLDIR)/modules.conf
TUNABLES := $(POLDIR)/tunables.conf
BOOLEANS := $(POLDIR)/booleans.conf

# install paths

DESTDIR = /boot
INSTALLDIR = $(DESTDIR)
LOADPATH = $(INSTALLDIR)/$(POLVER)

# default MLS sensitivity and category settings.
MLS_SENS ?= 16
MLS_CATS ?= 256

# enable MLS if requested.
ifneq ($(findstring -mls,$(TYPE)),)
	M4PARAM += -D enable_mls
	CHECKPOLICY += -M
endif

ifeq ($(NAME),)
	NAME := xenpolicy
endif

PV := $(shell $(CHECKPOLICY) -V |cut -f 1 -d ' ')

ifneq ($(OUTPUT_POLICY),)
	CHECKPOLICY += -c $(OUTPUT_POLICY)
	POLVER = $(NAME).$(OUTPUT_POLICY)
else
	POLVER +=$(NAME).$(PV)
endif


# determine the policy version and current kernel version if possible
M4PARAM += -D mls_num_sens=$(MLS_SENS) -D mls_num_cats=$(MLS_CATS) -D hide_broken_symptoms

M4SUPPORT = $(wildcard $(POLDIR)/support/*.spt)

ALL_LAYERS := $(filter-out $(MODDIR)/CVS,$(shell find $(wildcard $(MODDIR)/*) -maxdepth 0 -type d))

# sort here since it removes duplicates, which can happen
# when a generated file is already generated
DETECTED_MODS := $(sort $(foreach dir,$(ALL_LAYERS),$(wildcard $(dir)/*.te))) 

# modules.conf setting for policy configuration
MODENABLED := on

# extract settings from modules.conf
ENABLED_MODS := $(foreach mod,$(shell awk '/^[[:blank:]]*[[:alpha:]]/{ if ($$3 == "$(MODENABLED)") print $$1 }' $(MOD_CONF) 2> /dev/null),$(subst ./,,$(shell find -iname $(mod).te)))

ALL_MODULES := $(filter $(ENABLED_MODS),$(DETECTED_MODS))

ALL_INTERFACES := $(ALL_MODULES:.te=.if)
ALL_TE_FILES := $(ALL_MODULES)

PRE_TE_FILES := $(SECCLASS) $(ISIDS) $(AVS) $(M4SUPPORT) $(POLDIR)/mls 
POST_TE_FILES := $(POLDIR)/users $(POLDIR)/constraints

POLICY_SECTIONS := tmp/pre_te_files.conf tmp/all_interfaces.conf tmp/all_attrs_types.conf $(GLOBALBOOL) $(GLOBALTUN) tmp/only_te_rules.conf tmp/all_post.conf

########################################
#
# default action: build policy locally
#
default: policy

policy: $(POLVER)

install: $(LOADPATH)

load: tmp/load

########################################
#
# Build a binary policy locally
#
$(POLVER): policy.conf
	@echo "Compiling $(NAME) $(POLVER)"
	$(QUIET) $(CHECKPOLICY) $^ -o $@
# Uncomment line below to enable policies for devices
#	$(QUIET) $(CHECKPOLICY) -t Xen $^ -o $@

########################################
#
# Install a binary policy
#
$(LOADPATH): policy.conf
	@echo "Compiling and installing $(NAME) $(LOADPATH)"
	$(QUIET) $(CHECKPOLICY) $^ -o $@
# Uncomment line below to enable policies for devices
#	$(QUIET) $(CHECKPOLICY) -t Xen $^ -o $@

########################################
#
# Load the binary policy
#
tmp/load: reload
reload: $(LOADPATH) $(FCPATH)
	@echo "Loading $(NAME) $(LOADPATH)"
	$(QUIET) $(LOADPOLICY) $(LOADPATH)
	@touch tmp/load

########################################
#
# Construct a monolithic policy.conf
#
policy.conf: $(POLICY_SECTIONS)
	@echo "Creating $(NAME) policy.conf"
# checkpolicy can use the #line directives provided by -s for error reporting:
	$(QUIET) m4 -D self_contained_policy $(M4PARAM) -s $^ > $@

tmp/pre_te_files.conf: $(PRE_TE_FILES)
	@test -d tmp || mkdir -p tmp
	$(QUIET) cat $^ > $@

tmp/all_interfaces.conf: $(M4SUPPORT) $(ALL_INTERFACES)
ifeq ($(ALL_INTERFACES),)
	$(error No enabled modules! $(notdir $(MOD_CONF)) please create a modules.conf file)
endif
	@test -d tmp || mkdir -p tmp
	$(QUIET) cat $^ | sed -e s/dollarsstar/\$$\*/g > $@

tmp/all_te_files.conf: $(ALL_TE_FILES)
ifeq ($(ALL_TE_FILES),)
	$(error No enabled modules! $(notdir $(MOD_CONF)) please create a modules.conf file)
endif
	@test -d tmp || mkdir -p tmp
	$(QUIET) cat $^ > $@

tmp/post_te_files.conf: $(POST_TE_FILES)
	@test -d tmp || mkdir -p tmp
	$(QUIET) cat $^ > $@

# extract attributes and put them first. extract post te stuff
# like genfscon and put last.  portcon, nodecon, and netifcon
# is delayed since they are generated by m4
tmp/all_attrs_types.conf tmp/all_post.conf: tmp/only_te_rules.conf
tmp/only_te_rules.conf: tmp/all_te_files.conf tmp/post_te_files.conf
	$(QUIET) grep ^attribute tmp/all_te_files.conf > tmp/all_attrs_types.conf || true
	$(QUIET) grep '^type ' tmp/all_te_files.conf >> tmp/all_attrs_types.conf
	$(QUIET) cat tmp/post_te_files.conf > tmp/all_post.conf
	$(QUIET) grep '^sid ' tmp/all_te_files.conf >> tmp/all_post.conf || true
	$(QUIET) grep ^pirqcon tmp/all_te_files.conf >> \
                      tmp/all_post.conf || true
	$(QUIET) grep ^ioportcon tmp/all_te_files.conf >> \
                      tmp/all_post.conf || true
	$(QUIET) grep ^iomemcon tmp/all_te_files.conf >> \
                      tmp/all_post.conf || true
	$(QUIET) grep ^pcidevicecon tmp/all_te_files.conf >> \
                      tmp/all_post.conf || true
	$(QUIET) sed -r -e /^attribute/d -e '/^type /d' -e '/^sid /d' \
                     -e "/^pirqcon/d" -e "/^pcidevicecon/d" -e "/^ioportcon/d" \
                     -e "/^iomemcon/d" < tmp/all_te_files.conf \
                     > tmp/only_te_rules.conf

########################################
#
# Remove the dontaudit rules from the policy.conf
#
enableaudit: policy.conf
	@test -d tmp || mkdir -p tmp
	@echo "Removing dontaudit rules from policy.conf"
	$(QUIET) grep -v dontaudit policy.conf > tmp/policy.audit
	$(QUIET) mv tmp/policy.audit policy.conf

########################################
#
# Clean the built policies. 
#
clean:
	rm -fR tmp
	rm -f policy.conf
	rm -f $(POLVER)

.PHONY: default policy install load reload enableaudit clean
