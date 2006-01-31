XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

# hvmloader is a 32-bit protected mode binary.
# It belongs in /usr/lib, not /usr/lib64.
TARGET      := hvmloader/hvmloader
INSTALL_DIR := $(DESTDIR)/usr/lib/xen/boot

SUBDIRS :=
SUBDIRS += rombios
SUBDIRS += vgabios
SUBDIRS += acpi
SUBDIRS += vmxassist
SUBDIRS += hvmloader

.PHONY: all install clean

all:
	@set -e; if ! `which bcc 1>/dev/null 2>/dev/null`; then \
	echo "***********************************************************"; \
	echo "WARNING: Install dev86 package to build firmware!"; \
	echo "         (http://www.cix.co.uk/~mayday)"; \
	echo "***********************************************************"; \
	else \
	for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done; \
	fi


install: all
	[ -d $(INSTALL_DIR) ] || install -d -m0755 $(INSTALL_DIR)
	[ ! -e $(TARGET) ] || install -m0644 $(TARGET) $(INSTALL_DIR)

clean: 
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done
