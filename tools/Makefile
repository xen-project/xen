XEN_ROOT = ../
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS :=
SUBDIRS += libxutil
SUBDIRS += libxc
SUBDIRS += misc
SUBDIRS += examples
SUBDIRS += xentrace
SUBDIRS += python
SUBDIRS += xfrd
SUBDIRS += xcs
SUBDIRS += ioemu

.PHONY: all install clean check check_clean

all: check
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done

install: check
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done

clean: check_clean
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done

check:
	$(MAKE) -C check

check_clean:
	$(MAKE) -C check clean
