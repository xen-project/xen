XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

# hvmloader is a 32-bit protected mode binary.
TARGET      := hvmloader/hvmloader
INST_DIR := $(DESTDIR)$(XENFIRMWAREDIR)

SUBDIRS-y :=
SUBDIRS-$(CONFIG_SEABIOS) += seabios-dir
SUBDIRS-$(CONFIG_ROMBIOS) += rombios
SUBDIRS-$(CONFIG_ROMBIOS) += vgabios
SUBDIRS-$(CONFIG_ROMBIOS) += etherboot
SUBDIRS-y += hvmloader

seabios-dir:
	GIT=$(GIT) $(XEN_ROOT)/scripts/git-checkout.sh $(SEABIOS_UPSTREAM_URL) $(SEABIOS_UPSTREAM_TAG) seabios-dir
	cp seabios-config seabios-dir/.config;

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
	$(MAKE) subdirs-$@


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

subdir-distclean-seabios-dir: .phony
	rm -rf seabios-dir seabios-dir-remote

.PHONY: seabios-dir-force-update
seabios-dir-force-update:
	set -ex; \
	if [ "$(SEABIOS_UPSTREAM_TAG)" ]; then \
		cd seabios-dir-remote; \
		$(GIT) fetch origin; \
		$(GIT) reset --hard $(SEABIOS_UPSTREAM_TAG); \
	fi

subdir-clean-seabios-dir:
	set -e; if test -d seabios-dir/.; then \
		$(MAKE) -C seabios-dir clean; \
	fi
