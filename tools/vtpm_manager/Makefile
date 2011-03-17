XEN_ROOT = $(CURDIR)/../..

# Base definitions and rules
include $(XEN_ROOT)/tools/vtpm_manager/Rules.mk

SUBDIRS		= crypto tcs util manager migration
OPENSSL_HEADER	= /usr/include/openssl/crypto.h

.PHONY: all clean install
all clean install: %: subdirs-%

.PHONY: mrproper
mrproper:
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done


