XEN_ROOT = ../..

# Base definitions and rules
include $(XEN_ROOT)/tools/vtpm_manager/Rules.mk

SUBDIRS		= crypto tcs util manager migration
OPENSSL_HEADER	= /usr/include/openssl/crypto.h

.PHONY: all
all:
	for subdir in $(SUBDIRS); do          \
		$(MAKE) -C $$subdir $@;       \
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


.PHONY: mrproper
mrproper:
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done


