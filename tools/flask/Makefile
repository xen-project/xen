XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS :=
SUBDIRS += libflask
SUBDIRS += loadpolicy

.PHONY: all
all:
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done

.PHONY: install
install:
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done

.PHONY: clean
clean:
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done


