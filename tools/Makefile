XEN_ROOT = ../
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += libxc
SUBDIRS-y += xenstore
SUBDIRS-y += misc
SUBDIRS-y += examples
SUBDIRS-y += xentrace
SUBDIRS-$(CONFIG_XCUTILS) += xcutils
SUBDIRS-$(CONFIG_X86) += firmware
SUBDIRS-y += security
SUBDIRS-y += console
SUBDIRS-y += xenmon
SUBDIRS-y += guest-headers
SUBDIRS-$(VTPM_TOOLS) += vtpm_manager
SUBDIRS-$(VTPM_TOOLS) += vtpm
SUBDIRS-y += xenstat
SUBDIRS-y += libaio
SUBDIRS-y += blktap
SUBDIRS-y += libfsimage
SUBDIRS-$(XENFB_TOOLS) += xenfb
SUBDIRS-$(LIBXENAPI_BINDINGS) += libxen

# These don't cross-compile
ifeq ($(XEN_COMPILE_ARCH),$(XEN_TARGET_ARCH))
SUBDIRS-$(PYTHON_TOOLS) += python
SUBDIRS-$(PYTHON_TOOLS) += pygrub
endif

.PHONY: all
all: check
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) -C $$subdir $@; \
	done
	$(MAKE) ioemu

.PHONY: install
install: check
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) -C $$subdir $@; \
	done
	$(MAKE) ioemuinstall
	$(INSTALL_DIR) -p $(DESTDIR)/var/xen/dump
	$(INSTALL_DIR) -p $(DESTDIR)/var/log/xen

.PHONY: clean
clean: check_clean
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) -C $$subdir $@; \
	done
	$(MAKE) ioemuclean

.PHONY: distclean
distclean: clean

.PHONY: check
check:
	$(MAKE) -C check

.PHONY: check_clean
check_clean:
	$(MAKE) -C check clean

.PHONY: ioemu ioemuinstall ioemuclean
ifeq ($(CONFIG_IOEMU),y)
export IOEMU_DIR ?= ioemu
ioemu ioemuinstall:
	[ -f $(IOEMU_DIR)/config-host.mak ] || \
	  (cd $(IOEMU_DIR) && sh configure --prefix=/usr)
	$(MAKE) -C $(IOEMU_DIR) $(patsubst ioemu%,%,$@)
ioemuclean:
	$(MAKE) -C $(IOEMU_DIR) distclean
else
ioemu ioemuinstall ioemuclean:
endif

