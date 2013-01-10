obj-y += avc.o
obj-y += hooks.o
obj-y += flask_op.o

subdir-y += ss

CFLAGS += -I./include

AWK = awk

CONFIG_SHELL := $(shell if [ -x "$$BASH" ]; then echo $$BASH; \
          else if [ -x /bin/bash ]; then echo /bin/bash; \
          else echo sh; fi ; fi)

FLASK_H_DEPEND = policy/security_classes policy/initial_sids
AV_H_DEPEND = policy/access_vectors

FLASK_H_FILES = include/flask.h include/class_to_string.h include/initial_sid_to_string.h
AV_H_FILES = include/av_perm_to_string.h include/av_permissions.h
ALL_H_FILES = $(FLASK_H_FILES) $(AV_H_FILES)

$(obj-y) ss/built_in.o: $(ALL_H_FILES)

$(FLASK_H_FILES): $(FLASK_H_DEPEND)
	$(CONFIG_SHELL) policy/mkflask.sh $(AWK) $(FLASK_H_DEPEND)

$(AV_H_FILES): $(AV_H_DEPEND)
	$(CONFIG_SHELL) policy/mkaccess_vector.sh $(AWK) $(AV_H_DEPEND)

.PHONY: clean
clean::
	rm -f $(ALL_H_FILES) *.o $(DEPS)
