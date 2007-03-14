XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

# hvmloader is a 32-bit protected mode binary.
# It belongs in /usr/lib, not /usr/lib64.
TARGET      := hvmloader/hvmloader
INST_DIR := $(DESTDIR)/usr/lib/xen/boot

SUBDIRS :=
SUBDIRS += rombios rombios/32bit
SUBDIRS += vgabios
SUBDIRS += vmxassist
SUBDIRS += hvmloader

.PHONY: all
all:
	@set -e; if [ $$((`bcc -v 2>&1 | grep version | cut -d' ' -f 3 | awk -F. '{ printf "0x%02x%02x%02x", $$1, $$2, $$3}'`)) -lt $$((0x00100e)) ] ; then \
	echo "***********************************************************"; \
	echo "Require dev86 package version >= 0.16.14 to build firmware!"; \
	echo "(visit http://www.cix.co.uk/~mayday for more information)"; \
	echo "***********************************************************"; \
	else \
	for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done; \
	fi


.PHONY: install
install: all
	[ -d $(INST_DIR) ] || $(INSTALL_DIR) $(INST_DIR)
	[ ! -e $(TARGET) ] || $(INSTALL_DATA) $(TARGET) $(INST_DIR)

.PHONY: clean
clean: 
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done
