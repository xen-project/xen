XEN_ROOT = ../
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += check
SUBDIRS-y += include
SUBDIRS-y += libxc
SUBDIRS-y += flask
SUBDIRS-y += xenstore
SUBDIRS-y += misc
SUBDIRS-y += examples
SUBDIRS-y += xentrace
SUBDIRS-$(CONFIG_XCUTILS) += xcutils
SUBDIRS-$(CONFIG_X86) += firmware
SUBDIRS-$(ACM_SECURITY) += security
SUBDIRS-y += console
SUBDIRS-y += xenmon
SUBDIRS-$(VTPM_TOOLS) += vtpm_manager
SUBDIRS-$(VTPM_TOOLS) += vtpm
SUBDIRS-y += xenstat
SUBDIRS-y += libaio
SUBDIRS-y += blktap
SUBDIRS-y += libfsimage
SUBDIRS-$(LIBXENAPI_BINDINGS) += libxen
SUBDIRS-$(CONFIG_IOEMU) += ioemu

# These don't cross-compile
ifeq ($(XEN_COMPILE_ARCH),$(XEN_TARGET_ARCH))
SUBDIRS-$(PYTHON_TOOLS) += python
SUBDIRS-$(PYTHON_TOOLS) += pygrub
endif

# For the sake of linking, set the sys-root
ifneq ($(CROSS_COMPILE),)
CROSS_SYS_ROOT ?= /usr/$(CROSS_COMPILE:-=)/sys-root
export CROSS_SYS_ROOT
endif

.PHONY: all
all:
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) subdir-$@-$$subdir; \
	done

.PHONY: install
install:
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) subdir-$@-$$subdir; \
	done
	$(INSTALL_DIR) $(DESTDIR)/var/xen/dump
	$(INSTALL_DIR) $(DESTDIR)/var/log/xen
	$(INSTALL_DIR) $(DESTDIR)/var/lib/xen

.PHONY: clean distclean
clean distclean:
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) subdir-clean-$$subdir; \
	done

subdir-all-%:
	$(MAKE) -C $* all

subdir-clean-%:
	$(MAKE) -C $* clean

subdir-install-%:
	$(MAKE) -C $* install

ifneq ($(XEN_COMPILE_ARCH),$(XEN_TARGET_ARCH))
IOEMU_CONFIGURE_CROSS ?= --cross-prefix=$(CROSS_COMPILE) \
			 --interp-prefix=$(CROSS_SYS_ROOT)
endif

ioemu/config-host.mak:
	cd ioemu && XEN_TARGET_ARCH=$(XEN_TARGET_ARCH) sh configure --prefix=/usr \
		$(IOEMU_CONFIGURE_CROSS)

subdir-all-ioemu subdir-install-ioemu: ioemu/config-host.mak

subdir-clean-ioemu:
	$(MAKE) -C ioemu distclean

