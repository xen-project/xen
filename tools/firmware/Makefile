XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

# hvmloader is a 32-bit protected mode binary.
TARGET      := hvmloader/hvmloader
INST_DIR := $(DESTDIR)$(XENFIRMWAREDIR)

SUBDIRS :=
SUBDIRS += rombios
SUBDIRS += vgabios
SUBDIRS += etherboot
SUBDIRS += hvmloader

.PHONY: all
all:
	@set -e; if [ $$((`( bcc -v 2>&1 | grep version || echo 0.0.0 ) | cut -d' ' -f 3 | awk -F. '{ printf "0x%02x%02x%02x", $$1, $$2, $$3}'`)) -lt $$((0x00100e)) ] ; then \
	echo "==========================================================================="; \
	echo "Require dev86 rpm or bin86 & bcc debs version >= 0.16.14 to build firmware!"; \
	echo "(visit http://www.debath.co.uk/dev86/ for more information)"; \
	echo "==========================================================================="; \
	false ; \
	fi
	$(MAKE) subdirs-$@; \


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