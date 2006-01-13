XEN_ROOT = ../..

# Base definitions and rules
include $(XEN_ROOT)/tools/vtpm_manager/Rules.mk

SUBDIRS		= crypto tcs util manager
OPENSSL_HEADER	= /usr/include/openssl/crypto.h

all: build

build:
	if [ -e $(OPENSSL_HEADER) ]; then \
		@set -e; for subdir in $(SUBDIRS); do \
			$(MAKE) -C $$subdir $@; \
		done; \
	else \
		echo "*** Cannot build vtpm_manager: OpenSSL developement files missing."; \
	fi

install: build
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done

clean:
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done


mrproper:
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done


