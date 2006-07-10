XEN_ROOT = ../..

# Base definitions and rules
include $(XEN_ROOT)/tools/vtpm_manager/Rules.mk

SUBDIRS		= crypto tcs util manager migration
OPENSSL_HEADER	= /usr/include/openssl/crypto.h

.PHONY: all
all: build

.PHONY: build
build:
	@set -e; if [ -e $(OPENSSL_HEADER) ]; then            \
		if [ ! -e "migration/vtpm_ipc.c" ]; then        \
        		ln -s ../manager/vtpm_ipc.c migration;  \
		fi;                                    \
		for subdir in $(SUBDIRS); do          \
			$(MAKE) -C $$subdir $@;       \
		done;                                 \
	else \
		echo "*** Cannot build vtpm_manager: OpenSSL developement files missing."; \
	fi

.PHONY: install
install: build
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
	rm -f migration/vtpm_ipc.c
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done


