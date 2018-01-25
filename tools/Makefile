XEN_ROOT = $(CURDIR)/..

export PKG_CONFIG_DIR = $(CURDIR)/pkg-config

include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += libs
SUBDIRS-y += libxc
SUBDIRS-y += flask
SUBDIRS-y += fuzz
SUBDIRS-y += xenstore
SUBDIRS-y += misc
SUBDIRS-y += examples
SUBDIRS-y += hotplug
SUBDIRS-y += xentrace
SUBDIRS-$(CONFIG_XCUTILS) += xcutils
SUBDIRS-$(CONFIG_X86) += firmware
SUBDIRS-y += console
SUBDIRS-y += xenmon
SUBDIRS-y += xenstat
SUBDIRS-$(CONFIG_Linux) += memshr 
SUBDIRS-$(CONFIG_BLKTAP2) += blktap2
SUBDIRS-$(CONFIG_NetBSD) += xenbackendd
SUBDIRS-y += libfsimage
SUBDIRS-$(CONFIG_Linux) += libvchan

# do not recurse in to a dir we are about to delete
ifneq "$(MAKECMDGOALS)" "distclean"
SUBDIRS-$(CONFIG_QEMU_TRAD) += qemu-xen-traditional-dir
SUBDIRS-$(CONFIG_QEMU_XEN) += qemu-xen-dir
endif

SUBDIRS-y += xenpmd
SUBDIRS-y += libxl
SUBDIRS-$(CONFIG_GOLANG) += golang
SUBDIRS-y += xl
SUBDIRS-y += helpers
SUBDIRS-$(CONFIG_X86) += xenpaging
SUBDIRS-$(CONFIG_X86) += debugger/gdbsx
SUBDIRS-$(CONFIG_X86) += debugger/kdd
SUBDIRS-$(CONFIG_TESTS) += tests

# These don't cross-compile
ifeq ($(XEN_COMPILE_ARCH),$(XEN_TARGET_ARCH))
SUBDIRS-y += python
SUBDIRS-y += pygrub
SUBDIRS-$(OCAML_TOOLS) += ocaml
endif

ifeq ($(CONFIG_RUMP),y)
SUBDIRS-y := libs libxc xenstore
endif

# For the sake of linking, set the sys-root
ifneq ($(CROSS_COMPILE),)
CROSS_BIN_PATH ?= /usr/$(CROSS_COMPILE:-=)/bin
CROSS_SYS_ROOT ?= /usr/$(CROSS_COMPILE:-=)/sys-root
export CROSS_SYS_ROOT # exported for check/funcs.sh
export CROSS_BIN_PATH # exported for cross-install.sh
endif

.PHONY: build all
build all: subdirs-all

.PHONY: install
install:
	$(INSTALL_DIR) -m 700 $(DESTDIR)$(XEN_DUMP_DIR)
	$(INSTALL_DIR) $(DESTDIR)$(XEN_LOG_DIR)
	$(INSTALL_DIR) $(DESTDIR)$(XEN_RUN_DIR)
	$(INSTALL_DIR) $(DESTDIR)$(XEN_LIB_DIR)
	$(INSTALL_DIR) $(DESTDIR)$(XEN_RUN_STORED)
	$(INSTALL_DIR) $(DESTDIR)$(PKG_INSTALLDIR)
	$(MAKE) subdirs-install

.PHONY: uninstall
uninstall: D=$(DESTDIR)
uninstall:
	[ -d $(D)$(XEN_CONFIG_DIR) ] && mv -f $(D)$(XEN_CONFIG_DIR) $(D)$(XEN_CONFIG_DIR).old-`date +%s` || true
	rm -rf $(D)$(libdir)/xen
	rm -rf $(D)$(SHAREDIR)/xen
	rm -rf $(D)$(SHAREDIR)/qemu-xen
	$(MAKE) subdirs-uninstall

.PHONY: clean
clean: subdirs-clean
	rm -rf pkg-config

.PHONY: distclean
distclean: subdirs-distclean clean
	rm -rf qemu-xen-traditional-dir qemu-xen-traditional-dir-remote
	rm -rf qemu-xen-dir qemu-xen-dir-remote qemu-xen-build
	rm -rf ../config/Tools.mk config.h config.log config.status \
		config.cache autom4te.cache

ifneq ($(XEN_COMPILE_ARCH),$(XEN_TARGET_ARCH))
IOEMU_CONFIGURE_CROSS ?= --cross-prefix=$(CROSS_COMPILE) \
			 --interp-prefix=$(CROSS_SYS_ROOT)
endif

ifeq ($(XEN_TOOLS_RPATH),y)
QEMU_UPSTREAM_RPATH := -Wl,-rpath,$(LIBEXEC_LIB):$(libdir)
IOEMU_EXTRA_LDFLAGS := --extra-ldflags="-Wl,-rpath,$(libdir)"
else
QEMU_UPSTREAM_RPATH := -Wl,-rpath,$(LIBEXEC_LIB)
IOEMU_EXTRA_LDFLAGS :=
endif

QEMU_ROOT := $(shell if [ -d "$(QEMU_TRADITIONAL_LOC)" ]; then echo "$(QEMU_TRADITIONAL_LOC)"; else echo .; fi)
ifneq ($(QEMU_ROOT),.)
export QEMU_ROOT
endif

# Targets for external trees:
#  ${target}-dir-find
#    See if the directory exists and check it out if not.
#  ${target}-dir-force-update
#    Pull to the most recent update (as if you had checked it out for the
#    first time)
#  subdir-all-${target}-dir
#    Do "make all" for ${target}, including all prerequisites (such as 
#    configure)
#  subdir-install-${target}-dir
#    Do "make install" for $TARGET
#  subdir-clean-${target}-dir
#    Do "make clean" for $TARGET
#
# Directories for external trees:
#  ${target}-dir
#    Used for local builds.  Usually a link to ${target}-dir-remote
#  ${target}-dir-remote
#    Where remote repositories are cloned
#  ${target}
#    Where a copy of the source files are put when building a source 
#    tarball for release
#
# Expected variables:
#   ${TARGET}_URL
#     A url from which to clone a git repo
#   ${TARGET}_REVISION
#     The target revision to check out when doing "find" or "force-update"
#   ${TARGET}_INTREE
#     The directory where the subtree can be found (usually used when building
#     a source tarball)
#   ${TARGET}_LOC
#     The ultimate location of the source (either a local dir or remote URL)

# External target: qemu-xen-traditional
qemu-xen-traditional-dir-find:
	set -ex; \
	if test -d $(QEMU_TRADITIONAL_LOC); then \
		mkdir -p qemu-xen-traditional-dir; \
	else \
		export GIT=$(GIT); \
		$(XEN_ROOT)/scripts/git-checkout.sh $(QEMU_TRADITIONAL_LOC) $(QEMU_TRADITIONAL_REVISION) qemu-xen-traditional-dir; \
	fi

.PHONY: qemu-xen-traditional-dir-force-update
qemu-xen-traditional-dir-force-update: qemu-xen-traditional-dir-find
	set -ex; \
	if [ "$(QEMU_TRADITIONAL_REVISION)" ]; then \
		cd qemu-xen-traditional-dir-remote; \
		$(GIT) fetch origin; \
		$(GIT) reset --hard $(QEMU_TRADITIONAL_REVISION); \
	fi

qemu-traditional-recurse = \
	set -e; \
		$(buildmakevars2shellvars); \
		export CONFIG_BLKTAP1=n; \
		cd qemu-xen-traditional-dir; \
		$(1)

subdir-all-qemu-xen-traditional-dir: qemu-xen-traditional-dir-find
	$(call qemu-traditional-recurse,\
		$(QEMU_ROOT)/xen-setup \
		--extra-cflags="-D__XEN_TOOLS__ $(EXTRA_CFLAGS_QEMU_TRADITIONAL)" \
		$(IOEMU_EXTRA_LDFLAGS) \
		--cpu=$(IOEMU_CPU_ARCH) \
		$(IOEMU_CONFIGURE_CROSS); \
		$(MAKE) all \
	)

subdir-install-qemu-xen-traditional-dir: subdir-all-qemu-xen-traditional-dir
	$(call qemu-traditional-recurse,$(MAKE) install)

subdir-clean-qemu-xen-traditional-dir:
	set -e; if test -d qemu-xen-traditional-dir/.; then \
		$(MAKE) -C qemu-xen-traditional-dir clean; \
	fi
subdir-uninstall-qemu-xen-traditional-dir:
	rm -f $(D)$(bindir)/qemu-nbd*
	rm -f $(D)$(bindir)/qemu-img*

# External target: qemu-xen
qemu-xen-dir-find:
	if test -d $(QEMU_UPSTREAM_LOC) ; then \
		mkdir -p qemu-xen-dir; \
	else \
		export GIT=$(GIT); \
		$(XEN_ROOT)/scripts/git-checkout.sh $(QEMU_UPSTREAM_LOC) $(QEMU_UPSTREAM_REVISION) qemu-xen-dir ; \
	fi

.PHONY: qemu-xen-dir-force-update
qemu-xen-dir-force-update: qemu-xen-dir-find
	set -ex; \
	if [ "$(QEMU_UPSTREAM_REVISION)" ]; then \
		cd qemu-xen-dir-remote; \
		$(GIT) fetch origin; \
		$(GIT) reset --hard $(QEMU_UPSTREAM_REVISION); \
	fi

ifeq ($(debug),y)
QEMU_XEN_ENABLE_DEBUG := --enable-debug
else
QEMU_XEN_ENABLE_DEBUG :=
endif

subdir-all-qemu-xen-dir: qemu-xen-dir-find
	unset MAKELEVEL; \
	if test -d $(QEMU_UPSTREAM_LOC) ; then \
		source=$(QEMU_UPSTREAM_LOC); \
	else \
		source=$(XEN_ROOT)/tools/qemu-xen-dir; \
	fi; \
	mkdir -p qemu-xen-build; \
	cd qemu-xen-build; \
	if $$source/scripts/tracetool.py --check-backend --backend log ; then \
		enable_trace_backend='--enable-trace-backend=log'; \
	elif $$source/scripts/tracetool.py --check-backend --backend stderr ; then \
		enable_trace_backend='--enable-trace-backend=stderr'; \
	else \
		enable_trace_backend='' ; \
	fi ; \
	PKG_CONFIG_PATH=$(XEN_ROOT)/tools/pkg-config \
	$$source/configure --enable-xen --target-list=i386-softmmu \
		$(QEMU_XEN_ENABLE_DEBUG) \
		$$enable_trace_backend \
		--prefix=$(LIBEXEC) \
		--libdir=$(LIBEXEC_LIB) \
		--includedir=$(LIBEXEC_INC) \
		--source-path=$$source \
		--extra-cflags="-DXC_WANT_COMPAT_EVTCHN_API=1 \
		-DXC_WANT_COMPAT_GNTTAB_API=1 \
		-DXC_WANT_COMPAT_MAP_FOREIGN_API=1 \
		-DXC_WANT_COMPAT_DEVICEMODEL_API=1 \
		-I$(XEN_ROOT)/tools/include \
		-I$(XEN_ROOT)/tools/libs/toolcore/include \
		-I$(XEN_ROOT)/tools/libs/toollog/include \
		-I$(XEN_ROOT)/tools/libs/evtchn/include \
		-I$(XEN_ROOT)/tools/libs/gnttab/include \
		-I$(XEN_ROOT)/tools/libs/foreignmemory/include \
		-I$(XEN_ROOT)/tools/libs/devicemodel/include \
		-I$(XEN_ROOT)/tools/libxc/include \
		-I$(XEN_ROOT)/tools/xenstore/include \
		-I$(XEN_ROOT)/tools/xenstore/compat/include \
		$(EXTRA_CFLAGS_QEMU_XEN)" \
		--extra-ldflags="-L$(XEN_ROOT)/tools/libxc \
		-L$(XEN_ROOT)/tools/xenstore \
		-L$(XEN_ROOT)/tools/libs/toolcore \
		-L$(XEN_ROOT)/tools/libs/evtchn \
		-L$(XEN_ROOT)/tools/libs/gnttab \
		-L$(XEN_ROOT)/tools/libs/foreignmemory \
		-L$(XEN_ROOT)/tools/libs/devicemodel \
		-Wl,-rpath-link=$(XEN_ROOT)/tools/libs/toolcore \
		-Wl,-rpath-link=$(XEN_ROOT)/tools/libs/toollog \
		-Wl,-rpath-link=$(XEN_ROOT)/tools/libs/evtchn \
		-Wl,-rpath-link=$(XEN_ROOT)/tools/libs/gnttab \
		-Wl,-rpath-link=$(XEN_ROOT)/tools/libs/call \
		-Wl,-rpath-link=$(XEN_ROOT)/tools/libs/foreignmemory \
		-Wl,-rpath-link=$(XEN_ROOT)/tools/libs/devicemodel \
		$(QEMU_UPSTREAM_RPATH)" \
		--bindir=$(LIBEXEC_BIN) \
		--datadir=$(SHAREDIR)/qemu-xen \
		--localstatedir=$(localstatedir) \
		--disable-kvm \
		--disable-docs \
		--disable-guest-agent \
		--python=$(PYTHON) \
		$(CONFIG_QEMUU_EXTRA_ARGS) \
		--cpu=$(IOEMU_CPU_ARCH) \
		$(IOEMU_CONFIGURE_CROSS); \
	$(MAKE) all

subdir-install-qemu-xen-dir: subdir-all-qemu-xen-dir
	cd qemu-xen-build; \
	$(MAKE) install

subdir-clean-qemu-xen-dir:
	set -e; if test -d qemu-xen-build/.; then \
		$(MAKE) -C qemu-xen-build clean; \
	fi

subdir-uninstall-qemu-xen-dir: ;

subdir-clean-debugger/gdbsx subdir-distclean-debugger/gdbsx: .phony
	$(MAKE) -C debugger/gdbsx clean

subdir-install-debugger/gdbsx: .phony
	$(MAKE) -C debugger/gdbsx install

subdir-all-debugger/gdbsx: .phony
	$(MAKE) -C debugger/gdbsx all

subdir-uninstall-debugger/gdbsx: .phony
	$(MAKE) -C debugger/gdbsx uninstall

subdir-clean-debugger/kdd subdir-distclean-debugger/kdd: .phony
	$(MAKE) -C debugger/kdd clean

subdir-install-debugger/kdd: .phony
	$(MAKE) -C debugger/kdd install

subdir-uninstall-debugger/kdd: .phony
	$(MAKE) -C debugger/kdd uninstall

subdir-all-debugger/kdd: .phony
	$(MAKE) -C debugger/kdd all

subdir-distclean-firmware: .phony
	$(MAKE) -C firmware distclean

subtree-force-update:
ifeq ($(CONFIG_QEMU_XEN),y)
	$(MAKE) qemu-xen-dir-force-update
endif
ifeq ($(CONFIG_QEMU_TRAD),y)
	$(MAKE) qemu-xen-traditional-dir-force-update
endif
ifeq ($(CONFIG_X86),y)
	$(MAKE) -C firmware subtree-force-update
endif

subtree-force-update-all:
	$(MAKE) qemu-xen-dir-force-update
	$(MAKE) qemu-xen-traditional-dir-force-update
	$(MAKE) -C firmware subtree-force-update-all
