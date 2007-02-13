XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y = common ufs reiserfs iso9660 fat
SUBDIRS-y += $(shell ./check-libext2fs)

.PHONY: all
all install clean:
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) -C $$subdir $@; \
	done

distclean: clean
