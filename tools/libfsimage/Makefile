XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y = common ufs reiserfs
SUBDIRS-y += $(shell ./check-libext2fs)

.PHONY: all
all install clean:
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) -C $$subdir $@; \
	done

distclean: clean
