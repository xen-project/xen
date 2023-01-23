obj-y += avc.o
obj-y += hooks.o
obj-y += flask_op.o

obj-y += ss/

CFLAGS-y += -iquote $(obj)/include
CFLAGS-y += -I$(srcdir)/include

AWK = awk

FLASK_H_DEPEND := $(addprefix $(srcdir)/policy/,security_classes initial_sids)
AV_H_DEPEND := $(srcdir)/policy/access_vectors

FLASK_H_FILES := flask.h class_to_string.h initial_sid_to_string.h
AV_H_FILES := av_perm_to_string.h av_permissions.h
ALL_H_FILES := $(addprefix include/,$(FLASK_H_FILES) $(AV_H_FILES))

# Adding prerequisite to descending into ss/ folder only when not running
# `make *clean`.
ifeq ($(filter %/Makefile.clean,$(MAKEFILE_LIST)),)
$(addprefix $(obj)/,$(obj-y)) $(obj)/ss: $(addprefix $(obj)/,$(ALL_H_FILES))
endif
extra-y += $(ALL_H_FILES)

mkflask := $(srcdir)/policy/mkflask.sh
quiet_cmd_mkflask = MKFLASK $@
cmd_mkflask = $(SHELL) $(mkflask) $(AWK) $(obj)/include $(FLASK_H_DEPEND)

$(addprefix $(obj)/%/,$(FLASK_H_FILES)): $(FLASK_H_DEPEND) $(mkflask) FORCE
	$(call if_changed,mkflask)

mkaccess := $(srcdir)/policy/mkaccess_vector.sh
quiet_cmd_mkaccess = MKACCESS VECTOR $@
cmd_mkaccess = $(SHELL) $(mkaccess) $(AWK) $(obj)/include $(AV_H_DEPEND)

$(addprefix $(obj)/%/,$(AV_H_FILES)): $(AV_H_DEPEND) $(mkaccess) FORCE
	$(call if_changed,mkaccess)

obj-bin-$(CONFIG_XSM_FLASK_POLICY) += flask-policy.o
$(obj)/flask-policy.o: $(obj)/policy.bin

$(obj)/flask-policy.S: BINFILE_FLAGS := -i
$(obj)/flask-policy.S: $(srctree)/tools/binfile FORCE
	$(call if_changed,binfile,$(obj)/policy.bin xsm_flask_init_policy)
targets += flask-policy.S

FLASK_BUILD_DIR := $(abs_objtree)/$(obj)
POLICY_SRC := $(FLASK_BUILD_DIR)/xenpolicy-$(XEN_FULLVERSION)

$(obj)/policy.bin: FORCE
	$(MAKE) -f $(XEN_ROOT)/tools/flask/policy/Makefile.common \
	        -C $(XEN_ROOT)/tools/flask/policy \
	        FLASK_BUILD_DIR=$(FLASK_BUILD_DIR) POLICY_FILENAME=$(POLICY_SRC)
	cmp -s $(POLICY_SRC) $@ || cp $(POLICY_SRC) $@

clean-files := policy.* $(POLICY_SRC)
