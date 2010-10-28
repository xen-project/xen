XEN_ROOT = ..
include $(XEN_ROOT)/tools/Rules.mk

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
SUBDIRS-$(ACM_SECURITY) += security
SUBDIRS-y += console
SUBDIRS-y += xenmon
SUBDIRS-$(VTPM_TOOLS) += vtpm_manager
SUBDIRS-$(VTPM_TOOLS) += vtpm
SUBDIRS-y += xenstat
SUBDIRS-$(CONFIG_Linux) += libaio
SUBDIRS-$(CONFIG_Linux) += memshr 
SUBDIRS-$(CONFIG_Linux) += blktap
SUBDIRS-$(CONFIG_Linux) += blktap2
SUBDIRS-$(CONFIG_NetBSD) += libaio
SUBDIRS-$(CONFIG_NetBSD) += blktap2
SUBDIRS-$(CONFIG_NetBSD) += xenbackendd
SUBDIRS-y += libfsimage
SUBDIRS-$(LIBXENAPI_BINDINGS) += libxen
SUBDIRS-$(CONFIG_Linux) += fs-back
SUBDIRS-$(CONFIG_NetBSD) += fs-back

# do not recurse in to a dir we are about to delete
ifneq "$(MAKECMDGOALS)" "distclean"
SUBDIRS-$(CONFIG_IOEMU) += ioemu-dir
endif

SUBDIRS-y += xenpmd
SUBDIRS-y += libxl
SUBDIRS-y += remus
SUBDIRS-$(CONFIG_X86) += xenpaging
SUBDIRS-$(CONFIG_X86) += debugger/gdbsx
SUBDIRS-$(CONFIG_X86) += debugger/kdd

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
	rm -rf ioemu-dir ioemu-remote

ifneq ($(XEN_COMPILE_ARCH),$(XEN_TARGET_ARCH))
IOEMU_CONFIGURE_CROSS ?= --cpu=$(XEN_TARGET_ARCH) \
			 --cross-prefix=$(CROSS_COMPILE) \
			 --interp-prefix=$(CROSS_SYS_ROOT)
endif

ioemu/config-host.mak:
	cd ioemu && XEN_TARGET_ARCH=$(XEN_TARGET_ARCH) sh configure \
		--prefix=$(PREFIX) $(IOEMU_CONFIGURE_CROSS)

subdir-all-ioemu subdir-install-ioemu: ioemu/config-host.mak

subdir-clean-ioemu:
	$(MAKE) -C ioemu distclean

ioemu-dir-find:
	set -ex; \
	if test -d $(CONFIG_QEMU); then \
		rm -f ioemu-dir; \
		ln -sf $(CONFIG_QEMU) ioemu-dir; \
	else \
		if [ ! -d ioemu-remote ]; then \
			rm -rf ioemu-remote ioemu-remote.tmp; \
			mkdir ioemu-remote.tmp; rmdir ioemu-remote.tmp; \
			$(GIT) clone $(CONFIG_QEMU) ioemu-remote.tmp; \
			if [ "$(QEMU_TAG)" ]; then			\
				cd ioemu-remote.tmp;			\
				$(GIT) branch -D dummy >/dev/null 2>&1 ||:; \
				$(GIT) checkout -b dummy $(QEMU_TAG);	\
				cd ..;					\
			fi;						\
			mv ioemu-remote.tmp ioemu-remote; \
		fi; \
		rm -f ioemu-dir; \
		ln -sf ioemu-remote ioemu-dir; \
	fi
	set -e; \
		$(absolutify_xen_root); \
		$(buildmakevars2shellvars); \
		cd ioemu-dir; \
		./xen-setup $(IOEMU_CONFIGURE_CROSS)

subdir-all-ioemu-dir subdir-install-ioemu-dir: ioemu-dir-find

subdir-clean-ioemu-dir:
	set -e; if test -d ioemu-dir/.; then \
		$(absolutify_xen_root); \
		$(buildmakevars2shellvars); \
		$(MAKE) -C ioemu-dir clean; \
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
