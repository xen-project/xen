XEN_ROOT = ../
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
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
all: check
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) subdir-$@-$$subdir; \
	done
	$(MAKE) ioemu

.PHONY: install
install: check
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) subdir-$@-$$subdir; \
	done
	$(MAKE) ioemuinstall
	$(INSTALL_DIR) $(DESTDIR)/var/xen/dump
	$(INSTALL_DIR) $(DESTDIR)/var/log/xen
	$(INSTALL_DIR) $(DESTDIR)/var/lib/xen

.PHONY: clean
clean: check_clean
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) subdir-$@-$$subdir; \
	done
	$(MAKE) ioemuclean

.PHONY: distclean
distclean: clean

subdir-all-%:
	$(MAKE) -C $* all

subdir-clean-%:
	$(MAKE) -C $* clean

subdir-install-%:
	$(MAKE) -C $* install

.PHONY: check
check:
	$(MAKE) -C check

.PHONY: check_clean
check_clean:
	$(MAKE) -C check clean

.PHONY: ioemu ioemuinstall ioemuclean
ifeq ($(CONFIG_IOEMU),y)
IOEMU_DIR ?= ioemu
ifneq ($(XEN_COMPILE_ARCH),$(XEN_TARGET_ARCH))
IOEMU_CONFIGURE_CROSS ?= --cross-prefix=$(CROSS_COMPILE) \
			 --interp-prefix=$(CROSS_SYS_ROOT)
endif
ioemu ioemuinstall:
	[ -f $(IOEMU_DIR)/config-host.mak ] || \
	  ( cd $(IOEMU_DIR) && XEN_TARGET_ARCH=$(XEN_TARGET_ARCH) sh configure --prefix=/usr \
		$(IOEMU_CONFIGURE_CROSS) )
	$(MAKE) -C $(IOEMU_DIR) $(patsubst ioemu%,%,$@)
ioemuclean:
	$(MAKE) -C $(IOEMU_DIR) distclean
else
ioemu ioemuinstall ioemuclean:
endif

