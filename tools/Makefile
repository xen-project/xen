XEN_ROOT = $(CURDIR)/..

export PKG_CONFIG_DIR = $(CURDIR)/pkg-config

include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += libs
SUBDIRS-y += flask
SUBDIRS-y += fuzz
SUBDIRS-y += xs-clients
SUBDIRS-$(XENSTORE_XENSTORED) += xenstored
SUBDIRS-y += misc
SUBDIRS-y += examples
SUBDIRS-y += hotplug
SUBDIRS-y += xentrace
SUBDIRS-$(CONFIG_XCUTILS) += xcutils
SUBDIRS-$(CONFIG_X86) += firmware
SUBDIRS-y += console
SUBDIRS-y += xenmon
SUBDIRS-$(XENSTAT_XENTOP) += xentop
SUBDIRS-$(CONFIG_LIBFSIMAGE) += libfsimage
SUBDIRS-$(CONFIG_Linux) += vchan

# do not recurse in to a dir we are about to delete
ifneq "$(MAKECMDGOALS)" "distclean"
SUBDIRS-$(CONFIG_QEMU_XEN) += qemu-xen-dir
endif

SUBDIRS-y += xenpmd
SUBDIRS-$(CONFIG_GOLANG) += golang
SUBDIRS-y += xl
SUBDIRS-y += helpers
SUBDIRS-y += 9pfsd
SUBDIRS-$(CONFIG_X86) += xenpaging
SUBDIRS-$(CONFIG_X86) += debugger
SUBDIRS-$(CONFIG_TESTS) += tests

SUBDIRS-y += python
SUBDIRS-$(CONFIG_PYGRUB) += pygrub
SUBDIRS-$(OCAML_TOOLS) += ocaml

ifeq ($(CONFIG_RUMP),y)
SUBDIRS-y := libs
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
	$(INSTALL_DIR) $(DESTDIR)$(XEN_LIB_DIR)
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
		enable_trace_backend="--enable-trace-backends=log"; \
	elif $$source/scripts/tracetool.py --check-backend --backend stderr ; then \
		enable_trace_backend='--enable-trace-backends=stderr'; \
	else \
		enable_trace_backend='' ; \
	fi ; \
	if [ "$(CONFIG_9PFS)" = "y" ]; then \
		virtfs='--enable-virtfs' ; \
	elif [ "$(CONFIG_9PFS)" = "n" ]; then \
		virtfs='--disable-virtfs' ; \
	else \
		virtfs='' ; \
	fi ; \
	PKG_CONFIG_PATH=$(XEN_ROOT)/tools/pkg-config$${PKG_CONFIG_PATH:+:$${PKG_CONFIG_PATH}} \
	$$source/configure --enable-xen --target-list=i386-softmmu \
		$(QEMU_XEN_ENABLE_DEBUG) \
		$$enable_trace_backend \
		--prefix=$(prefix) \
		--libdir=$(LIBEXEC_LIB) \
		--includedir=$(LIBEXEC_INC) \
		--extra-cflags="-DXC_WANT_COMPAT_EVTCHN_API=1 \
		-DXC_WANT_COMPAT_GNTTAB_API=1 \
		-DXC_WANT_COMPAT_MAP_FOREIGN_API=1 \
		-DXC_WANT_COMPAT_DEVICEMODEL_API=1 \
		$(EXTRA_CFLAGS_QEMU_XEN)" \
		--extra-ldflags="$(QEMU_UPSTREAM_RPATH)" \
		--bindir=$(LIBEXEC_BIN) \
		--datadir=$(SHAREDIR)/qemu-xen \
		--localstatedir=$(localstatedir) \
		--docdir=$(LIBEXEC)/share/doc \
		--mandir=$(LIBEXEC)/share/man \
		--libexecdir=$(LIBEXEC)/libexec \
		--firmwarepath=$(LIBEXEC)/share/qemu-firmware \
		--disable-kvm \
		--disable-docs \
		--disable-guest-agent \
		--python=$(PYTHON) \
		$(CONFIG_QEMUU_EXTRA_ARGS) \
		--cpu=$(IOEMU_CPU_ARCH) \
		$(IOEMU_CONFIGURE_CROSS) \
		$$virtfs; \
	$(MAKE) all

subdir-install-qemu-xen-dir: subdir-all-qemu-xen-dir
	cd qemu-xen-build; \
	$(MAKE) install

subdir-clean-qemu-xen-dir:
	set -e; if test -d qemu-xen-build/.; then \
		$(MAKE) -C qemu-xen-build clean; \
	fi

subdir-uninstall-qemu-xen-dir: ;

subtree-force-update:
ifeq ($(CONFIG_QEMU_XEN),y)
	$(MAKE) qemu-xen-dir-force-update
endif
ifeq ($(CONFIG_X86),y)
	$(MAKE) -C firmware subtree-force-update
endif
