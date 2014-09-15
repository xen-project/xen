XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

# hvmloader is a 32-bit protected mode binary.
TARGET      := hvmloader/hvmloader
INST_DIR := $(DESTDIR)$(XENFIRMWAREDIR)

SUBDIRS-y :=
ifeq ($(OVMF_PATH),)
SUBDIRS-$(CONFIG_OVMF) += ovmf-dir
endif
ifeq ($(SEABIOS_PATH),)
SUBDIRS-$(CONFIG_SEABIOS) += seabios-dir
endif
SUBDIRS-$(CONFIG_ROMBIOS) += rombios
SUBDIRS-$(CONFIG_ROMBIOS) += vgabios
SUBDIRS-$(CONFIG_ROMBIOS) += etherboot
SUBDIRS-y += hvmloader

LD32BIT-$(CONFIG_FreeBSD) := LD32BIT_FLAG=-melf_i386_fbsd

ovmf-dir:
	GIT=$(GIT) $(XEN_ROOT)/scripts/git-checkout.sh $(OVMF_UPSTREAM_URL) $(OVMF_UPSTREAM_REVISION) ovmf-dir
	cp ovmf-makefile ovmf-dir/Makefile;

seabios-dir:
	GIT=$(GIT) $(XEN_ROOT)/scripts/git-checkout.sh $(SEABIOS_UPSTREAM_URL) $(SEABIOS_UPSTREAM_REVISION) seabios-dir
	$(MAKE) -C seabios-dir defconfig

.PHONY: all
all: $(SUBDIRS-y)
ifeq ($(CONFIG_ROMBIOS),y)
	@set -e; if [ $$((`( bcc -v 2>&1 | grep version || echo 0.0.0 ) | cut -d' ' -f 3 | awk -F. '{ printf "0x%02x%02x%02x", $$1, $$2, $$3}'`)) -lt $$((0x00100e)) ] ; then \
	echo "==========================================================================="; \
	echo "Require dev86 rpm or bin86 & bcc debs version >= 0.16.14 to build firmware!"; \
	echo "(visit http://www.debath.co.uk/dev86/ for more information)"; \
	echo "==========================================================================="; \
	false ; \
	fi
endif
	$(MAKE) $(LD32BIT-y) CC=$(CC) PYTHON=$(PYTHON) subdirs-$@


.PHONY: install
install: all
	[ -d $(INST_DIR) ] || $(INSTALL_DIR) $(INST_DIR)
	[ ! -e $(TARGET) ] || $(INSTALL_DATA) $(TARGET) $(INST_DIR)

.PHONY: clean
clean: subdirs-clean

.PHONY: distclean
distclean: subdirs-distclean

subdir-distclean-etherboot: .phony
	$(MAKE) -C etherboot distclean

subdir-distclean-ovmf: .phony
	rm -rf ovmf-dir ovmf-dir-remote

subdir-distclean-seabios-dir: .phony
	rm -rf seabios-dir seabios-dir-remote

.PHONY: ovmf-dir-force-update
ovmf-dir-force-update: ovmf-dir
	set -ex; \
	if [ "$(OVMF_UPSTREAM_REVISION)" ]; then \
		cd ovmf-dir-remote; \
		$(GIT) fetch origin; \
		$(GIT) reset --hard $(OVMF_UPSTREAM_REVISION); \
	fi

subdir-clean-ovmf:
	set -e; if test -d ovmf-dir/.; then \
		$(MAKE) -C ovmf-dir clean; \
	fi

.PHONY: seabios-dir-force-update
seabios-dir-force-update: seabios-dir
	set -ex; \
	if [ "$(SEABIOS_UPSTREAM_REVISION)" ]; then \
		cd seabios-dir-remote; \
		$(GIT) fetch origin; \
		$(GIT) reset --hard $(SEABIOS_UPSTREAM_REVISION); \
	fi

subdir-clean-seabios-dir:
	set -e; if test -d seabios-dir/.; then \
		$(MAKE) -C seabios-dir clean; \
	fi

subtree-force-update:
ifeq ($(CONFIG_SEABIOS),y)
	$(MAKE) seabios-dir-force-update
endif
ifeq ($(CONFIG_OVMF),y)
	$(MAKE) ovmf-dir-force-update
endif

subtree-force-update-all:
	$(MAKE) seabios-dir-force-update
	$(MAKE) ovmf-dir-force-update
