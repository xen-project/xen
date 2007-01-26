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


.PHONY: install
install: all
	[ -d $(INST_DIR) ] || $(INSTALL_DIR) $(INST_DIR)
	[ ! -e $(TARGET) ] || $(INSTALL_DATA) $(TARGET) $(INST_DIR)

.PHONY: clean
clean: 
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done
