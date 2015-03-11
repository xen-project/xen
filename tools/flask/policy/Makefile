XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

########################################
#
# Configurable portions of the Makefile
#
########################################

CONFIG_MLS ?= n

# Number of available MLS sensitivities and categories.
# The sensitivities will be s0 to s(MLS_SENS-1).  Dominance will be in
# increasing numerical order with s0 being lowest.
MLS_SENS ?= 16
# The categories will be c0 to c(MLS_CATS-1).
MLS_CATS ?= 256

# executable paths
CHECKPOLICY ?= checkpolicy
M4 ?= m4

# Output security policy version.  Leave unset to autodetect.
OUTPUT_POLICY ?= $(BEST_POLICY_VER)

########################################
#
# End of configuration options
#
########################################

POLICY_FILENAME = xenpolicy-$(shell $(MAKE) -C $(XEN_ROOT)/xen xenversion --no-print-directory)
POLICY_LOADPATH = /boot

# List of policy versions supported by the hypervisor
POLICY_VER_LIST_HV = 24 30

# policy source layout
POLDIR := policy
MODDIR := $(POLDIR)/modules

# Classes and access vectors defined in the hypervisor. Changes to these require
# a recompile of both the hypervisor and security policy.
FLASKDIR := ../../../xen/xsm/flask/policy
SECCLASS := $(FLASKDIR)/security_classes
ISID_DECLS := $(FLASKDIR)/initial_sids
AVS := $(FLASKDIR)/access_vectors

# Additional classes and access vectors defined by local policy
SECCLASS += $(POLDIR)/security_classes
AVS += $(POLDIR)/access_vectors

# Other policy components
M4SUPPORT := $(wildcard $(POLDIR)/support/*.spt)
MLSSUPPORT := $(POLDIR)/mls
USERS := $(POLDIR)/users
CONSTRAINTS := $(POLDIR)/constraints
ISID_DEFS := $(POLDIR)/initial_sids
DEV_OCONS := $(POLDIR)/device_contexts

# config file paths
GLOBALTUN := $(POLDIR)/global_tunables
MOD_CONF := $(POLDIR)/modules.conf

# checkpolicy can use the #line directives provided by -s for error reporting:
M4PARAM := -D self_contained_policy -s

# The output of checkpolicy -V is "30 (compatibility range 30-15)", and the
# first word of the output is the maximum policy version supported.
CHECKPOLICY_VER_MAX := $(firstword $(shell $(CHECKPOLICY) -V))

# Find the highest version supported by both the hypervisor and checkpolicy
BEST_POLICY_VER := $(shell best=24; for ver in $(POLICY_VER_LIST_HV); do if test $$ver -le $(CHECKPOLICY_VER_MAX); then best=$$ver; fi; done; echo $$best)

CHECKPOLICY_PARAM := -t Xen -c $(OUTPUT_POLICY)

# enable MLS if requested.
ifneq ($(CONFIG_MLS),n)
	M4PARAM += -D enable_mls
	CHECKPOLICY_PARAM += -M
endif

# Always define these because they are referenced even in non-MLS policy
M4PARAM += -D mls_num_sens=$(MLS_SENS) -D mls_num_cats=$(MLS_CATS)


# Find modules
ALL_LAYERS := $(filter-out $(MODDIR)/CVS,$(shell find $(wildcard $(MODDIR)/*) -maxdepth 0 -type d))

# sort here since it removes duplicates, which can happen
# when a generated file is already generated
DETECTED_MODS := $(sort $(foreach dir,$(ALL_LAYERS),$(wildcard $(dir)/*.te)))

# modules.conf setting for policy configuration
MODENABLED := on

# extract settings from modules.conf
ENABLED_MODS := $(foreach mod,$(shell awk '/^[ \t]*[a-z]/{ if ($$3 == "$(MODENABLED)") print $$1 }' $(MOD_CONF) 2> /dev/null),$(subst ./,,$(shell find -iname $(mod).te)))

ALL_MODULES := $(filter $(ENABLED_MODS),$(DETECTED_MODS))

ALL_INTERFACES := $(ALL_MODULES:.te=.if)

# The order of these files is important
POLICY_SECTIONS := $(SECCLASS) $(ISID_DECLS) $(AVS)
POLICY_SECTIONS += $(M4SUPPORT) $(MLSSUPPORT)
POLICY_SECTIONS += $(ALL_INTERFACES)
POLICY_SECTIONS += $(GLOBALTUN)
POLICY_SECTIONS += $(ALL_MODULES)
POLICY_SECTIONS += $(USERS) $(CONSTRAINTS) $(ISID_DEFS) $(DEV_OCONS)

all: $(POLICY_FILENAME)

install: $(POLICY_FILENAME)
	$(INSTALL_DIR) $(DESTDIR)/$(POLICY_LOADPATH)
	$(INSTALL_DATA) $^ $(DESTDIR)/$(POLICY_LOADPATH)

$(POLICY_FILENAME): policy.conf
	$(CHECKPOLICY) $(CHECKPOLICY_PARAM) $^ -o $@

policy.conf: $(POLICY_SECTIONS)
	$(M4) $(M4PARAM) $^ > $@

clean:
	$(RM) tmp policy.conf $(POLICY_FILENAME)

distclean: clean

.PHONY: all install clean distclean
