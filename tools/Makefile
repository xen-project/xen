XEN_ROOT = $(CURDIR)/..
include $(XEN_ROOT)/tools/Rules.mk

ifneq ($(CONFIG_SYSTEM_LIBAIO),y)
SUBDIRS-libaio := libaio
endif

SUBDIRS-y :=
SUBDIRS-y += check
SUBDIRS-y += include
SUBDIRS-y += libxc
SUBDIRS-y += flask
SUBDIRS-y += xenstore
SUBDIRS-y += misc
SUBDIRS-y += examples
SUBDIRS-y += hotplug
SUBDIRS-y += xentrace
SUBDIRS-$(CONFIG_XCUTILS) += xcutils
SUBDIRS-$(CONFIG_X86) += firmware
SUBDIRS-y += console
SUBDIRS-y += xenmon
SUBDIRS-$(VTPM_TOOLS) += vtpm_manager
SUBDIRS-$(VTPM_TOOLS) += vtpm
SUBDIRS-y += xenstat
SUBDIRS-$(CONFIG_Linux) += $(SUBDIRS-libaio)
SUBDIRS-$(CONFIG_Linux) += memshr 
SUBDIRS-$(CONFIG_Linux) += blktap
SUBDIRS-$(CONFIG_Linux) += blktap2
SUBDIRS-$(CONFIG_NetBSD) += $(SUBDIRS-libaio)
SUBDIRS-$(CONFIG_NetBSD) += blktap2
SUBDIRS-$(CONFIG_NetBSD) += xenbackendd
SUBDIRS-y += libfsimage
SUBDIRS-$(LIBXENAPI_BINDINGS) += libxen
SUBDIRS-y += libvchan

# do not recurse in to a dir we are about to delete
ifneq "$(MAKECMDGOALS)" "distclean"
SUBDIRS-$(CONFIG_IOEMU) += qemu-xen-traditional-dir
SUBDIRS-$(CONFIG_IOEMU) += qemu-xen-dir
endif

SUBDIRS-y += xenpmd
SUBDIRS-y += libxl
SUBDIRS-y += remus
SUBDIRS-$(CONFIG_X86) += xenpaging
SUBDIRS-$(CONFIG_X86) += debugger/gdbsx
SUBDIRS-$(CONFIG_X86) += debugger/kdd
SUBDIRS-$(CONFIG_TESTS) += tests

# These don't cross-compile
ifeq ($(XEN_COMPILE_ARCH),$(XEN_TARGET_ARCH))
SUBDIRS-$(PYTHON_TOOLS) += python
SUBDIRS-$(PYTHON_TOOLS) += pygrub
SUBDIRS-$(OCAML_TOOLS) += ocaml
endif

# For the sake of linking, set the sys-root
ifneq ($(CROSS_COMPILE),)
CROSS_BIN_PATH ?= /usr/$(CROSS_COMPILE:-=)/bin
CROSS_SYS_ROOT ?= /usr/$(CROSS_COMPILE:-=)/sys-root
export CROSS_SYS_ROOT # exported for check/funcs.sh
export CROSS_BIN_PATH # exported for cross-install.sh
endif

.PHONY: all
all: subdirs-all

.PHONY: install
install: subdirs-install
	$(INSTALL_DIR) $(DESTDIR)/var/xen/dump
	$(INSTALL_DIR) $(DESTDIR)/var/log/xen
	$(INSTALL_DIR) $(DESTDIR)/var/lib/xen
	$(INSTALL_DIR) $(DESTDIR)/var/lock/subsys

.PHONY: clean
clean: subdirs-clean

.PHONY: distclean
distclean: subdirs-distclean
	rm -rf qemu-xen-traditional-dir qemu-xen-traditional-dir-remote
	rm -rf qemu-xen-dir qemu-xen-dir-remote

ifneq ($(XEN_COMPILE_ARCH),$(XEN_TARGET_ARCH))
IOEMU_CONFIGURE_CROSS ?= --cpu=$(XEN_TARGET_ARCH) \
			 --cross-prefix=$(CROSS_COMPILE) \
			 --interp-prefix=$(CROSS_SYS_ROOT)
endif

QEMU_ROOT := $(shell if [ -d "$(CONFIG_QEMU)" ]; then echo "$(CONFIG_QEMU)"; else echo .; fi)
ifneq ($(QEMU_ROOT),.)
export QEMU_ROOT
endif

qemu-xen-traditional-dir-find:
	set -ex; \
	if test -d $(CONFIG_QEMU); then \
		mkdir -p qemu-xen-traditional-dir; \
	else \
		export GIT=$(GIT); \
		$(XEN_ROOT)/scripts/git-checkout.sh $(CONFIG_QEMU) $(QEMU_TAG) qemu-xen-traditional-dir; \
	fi

qemu-xen-dir-find:
	if test -d $(QEMU_UPSTREAM_URL) ; then \
		mkdir -p qemu-xen-dir; \
	else \
		export GIT=$(GIT); \
		$(XEN_ROOT)/scripts/git-checkout.sh $(QEMU_UPSTREAM_URL) $(QEMU_UPSTREAM_REVISION) qemu-xen-dir ; \
	fi

.PHONY: qemu-xen-traditional-dir-force-update
qemu-xen-traditional-dir-force-update:
	set -ex; \
	if [ "$(QEMU_TAG)" ]; then \
		cd qemu-xen-traditional-dir-remote; \
		$(GIT) fetch origin; \
		$(GIT) reset --hard $(QEMU_TAG); \
	fi

subdir-all-qemu-xen-traditional-dir subdir-install-qemu-xen-traditional-dir: qemu-xen-traditional-dir-find
	set -e; \
		$(buildmakevars2shellvars); \
		cd qemu-xen-traditional-dir; \
		$(QEMU_ROOT)/xen-setup $(IOEMU_CONFIGURE_CROSS); \
		$(MAKE) install

subdir-clean-qemu-xen-traditional-dir:
	set -e; if test -d qemu-xen-traditional-dir/.; then \
		$(buildmakevars2shellvars); \
		$(MAKE) -C qemu-xen-traditional-dir clean; \
	fi

.PHONY: qemu-xen-dir-force-update
qemu-xen-dir-force-update:
	set -ex; \
	if [ "$(QEMU_UPSTREAM_REVISION)" ]; then \
		cd qemu-xen-dir-remote; \
		$(GIT) fetch origin; \
		$(GIT) reset --hard $(QEMU_UPSTREAM_REVISION); \
	fi

subdir-all-qemu-xen-dir subdir-install-qemu-xen-dir: qemu-xen-dir-find
	if test -d $(QEMU_UPSTREAM_URL) ; then \
		source=$(QEMU_UPSTREAM_URL); \
	else \
		source=.; \
	fi; \
	cd qemu-xen-dir; \
	$$source/configure --enable-xen --target-list=i386-softmmu \
		--source-path=$$source \
		--extra-cflags="-I$(XEN_ROOT)/tools/include \
		-I$(XEN_ROOT)/tools/libxc \
		-I$(XEN_ROOT)/tools/xenstore" \
		--extra-ldflags="-L$(XEN_ROOT)/tools/libxc \
		-L$(XEN_ROOT)/tools/xenstore" \
		--bindir=$(LIBEXEC) \
		--disable-kvm \
		--python=$(PYTHON) \
		$(IOEMU_CONFIGURE_CROSS); \
	$(MAKE) install

subdir-clean-qemu-xen-dir:
	set -e; if test -d qemu-xen-dir/.; then \
		$(buildmakevars2shellvars); \
		$(MAKE) -C qemu-xen-dir clean; \
	fi

subdir-clean-debugger/gdbsx subdir-distclean-debugger/gdbsx: .phony
	$(MAKE) -C debugger/gdbsx clean

subdir-install-debugger/gdbsx: .phony
	$(MAKE) -C debugger/gdbsx install

subdir-all-debugger/gdbsx: .phony
	$(MAKE) -C debugger/gdbsx all


subdir-clean-debugger/kdd subdir-distclean-debugger/kdd: .phony
	$(MAKE) -C debugger/kdd clean

subdir-install-debugger/kdd: .phony
	$(MAKE) -C debugger/kdd install

subdir-all-debugger/kdd: .phony
	$(MAKE) -C debugger/kdd all

subdir-distclean-firmware: .phony
	$(MAKE) -C firmware distclean
