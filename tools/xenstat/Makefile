XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS :=
SUBDIRS += libxenstat
SUBDIRS += xentop

.PHONY: all install clean

all install clean:
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done
