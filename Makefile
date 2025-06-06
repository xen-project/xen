#
# Grand Unified Makefile for Xen.
#

# Default target must appear before any include lines
.PHONY: all
all: dist

-include config/Toplevel.mk
SUBSYSTEMS?=xen tools stubdom docs
TARGS_DIST=$(patsubst %, dist-%, $(SUBSYSTEMS))
TARGS_INSTALL=$(patsubst %, install-%, $(SUBSYSTEMS))
TARGS_UNINSTALL=$(patsubst %, uninstall-%, $(SUBSYSTEMS))
TARGS_BUILD=$(patsubst %, build-%, $(SUBSYSTEMS))
TARGS_CLEAN=$(patsubst %, clean-%, $(SUBSYSTEMS))
TARGS_DISTCLEAN=$(patsubst %, distclean-%, $(SUBSYSTEMS))

export XEN_ROOT=$(CURDIR)
include Config.mk

.PHONY: mini-os-dir
mini-os-dir:
	if [ ! -d $(XEN_ROOT)/extras/mini-os ]; then \
		GIT=$(GIT) $(XEN_ROOT)/scripts/git-checkout.sh \
			$(MINIOS_UPSTREAM_URL) \
			$(MINIOS_UPSTREAM_REVISION) \
			$(XEN_ROOT)/extras/mini-os ; \
	fi

.PHONY: mini-os-dir-force-update
mini-os-dir-force-update: mini-os-dir
	set -ex; \
	if [ "$(MINIOS_UPSTREAM_REVISION)" ]; then \
		cd extras/mini-os-remote; \
		$(GIT) fetch origin; \
		$(GIT) reset --hard $(MINIOS_UPSTREAM_REVISION); \
	fi

export XEN_TARGET_ARCH
export DESTDIR

.PHONY: %-tools-public-headers
%-tools-public-headers:
	$(MAKE) -C tools/include $*

# build and install everything into the standard system directories
.PHONY: install
install: $(TARGS_INSTALL)

.PHONY: build
build: $(TARGS_BUILD)

.PHONY: build-xen
build-xen:
	$(MAKE) -C xen build

.PHONY: %_defconfig
%_defconfig:
	$(MAKE) -C xen $@

.PHONY: build-tools
build-tools: build-tools-public-headers
	$(MAKE) -C tools build

.PHONY: build-tools-oxenstored
build-tools-oxenstored: build-tools-public-headers
	$(MAKE) -s -C tools/ocaml clean
	$(MAKE) -s -C tools/libs
	$(MAKE) -C tools/ocaml build-tools-oxenstored

.PHONY: build-stubdom
build-stubdom: mini-os-dir build-tools-public-headers
	$(MAKE) -C stubdom build
ifeq (x86_64,$(XEN_TARGET_ARCH))
	XEN_TARGET_ARCH=x86_32 $(MAKE) -C stubdom pv-grub-if-enabled
endif

define do-subtree
$(1)/%: FORCE
	$$(MAKE) -C $(1) $$*
endef

$(foreach m,$(wildcard */Makefile),$(eval $(call do-subtree,$(patsubst %/Makefile,%,$(m)))))

.PHONY: build-docs
build-docs:
	$(MAKE) -C docs build

# The test target is for unit tests that can run without an installation.  Of
# course, many tests require a machine running Xen itself, and these are
# handled elsewhere.
.PHONY: test
test:
	$(MAKE) -C tools/python test

run-tests-%: build-tools-public-headers tools/tests/%/
	$(MAKE) -C tools/tests/$* run

# For most targets here,
#   make COMPONENT-TARGET
# is implemented, more or less, by
#   make -C COMPONENT TARGET
#
# Each rule that does this needs to have dependencies on any
# other COMPONENTs that have to be processed first.  See
# The install-tools target here for an example.
#
# dist* targets are special: these do not occur in lower-level
# Makefiles.  Instead, these are all implemented only here.
# They run the appropriate install targets with DESTDIR set.
#
# Also, we have a number of targets COMPONENT which run
# dist-COMPONENT, for convenience.
#
# The Makefiles invoked with -C from the toplevel should
# generally have the following targets:
#       all  build  install  clean  distclean


.PHONY: dist
dist: DESTDIR=$(DISTDIR)/install
dist: $(TARGS_DIST) dist-misc

dist-misc:
	$(INSTALL_DIR) $(DISTDIR)/
	$(INSTALL_DATA) ./COPYING $(DISTDIR)
	$(INSTALL_DATA) ./README $(DISTDIR)
	$(INSTALL_PROG) ./install.sh $(DISTDIR)


dist-%: DESTDIR=$(DISTDIR)/install
dist-%: install-%
	@: # do nothing

.PHONY: xen tools stubdom docs
xen: dist-xen
tools: dist-tools
stubdom: dist-stubdom
docs: dist-docs

.PHONY: install-xen
install-xen:
	$(MAKE) -C xen install

.PHONY: install-tools
install-tools: install-tools-public-headers
	$(MAKE) -C tools install

.PHONY: install-stubdom
install-stubdom: mini-os-dir install-tools-public-headers
	$(MAKE) -C stubdom install
ifeq (x86_64,$(XEN_TARGET_ARCH))
	XEN_TARGET_ARCH=x86_32 $(MAKE) -C stubdom install-grub-if-enabled
endif

.PHONY: tools/firmware/seabios-dir-force-update
tools/firmware/seabios-dir-force-update:
	$(MAKE) -C tools/firmware seabios-dir-force-update

.PHONY: tools/firmware/ovmf-dir-force-update
tools/firmware/ovmf-dir-force-update:
	$(MAKE) -C tools/firmware ovmf-dir-force-update

.PHONY: install-docs
install-docs:
	$(MAKE) -C docs install

# We only have build-tests install-tests, not uninstall-tests etc.
.PHONY: build-tests
build-tests: build-xen
	$(MAKE) -C xen tests

.PHONY: install-tests
install-tests: install-xen
	$(MAKE) -C xen $@

# build xen and the tools and place them in the install
# directory. 'make install' should then copy them to the normal system
# directories
.PHONY: world
world: 
	$(MAKE) clean
	$(MAKE) dist

# Package a build in a debball file, that is inside a .deb format
# container to allow for easy and clean removal. This is not intended
# to be a full featured policy compliant .deb package.
.PHONY: debball
debball: dist
	fakeroot sh ./tools/misc/mkdeb $(XEN_ROOT) $$($(MAKE) -C xen xenversion --no-print-directory)

# Package a build in an rpmball file, that is inside a .rpm format
# container to allow for easy and clean removal. This is not intended
# to be a full featured policy compliant .rpm package.
.PHONY: rpmball
rpmball: dist
	bash ./tools/misc/mkrpm $(XEN_ROOT) $$($(MAKE) -C xen xenversion --no-print-directory)

.PHONY: subtree-force-update
subtree-force-update: mini-os-dir-force-update
	$(MAKE) -C tools subtree-force-update

# Make a source tarball, including qemu sub-trees.
#
# src-tarball will use "git describe" for the version number.  This
# will have the most recent tag, number of commits since that tag, and
# git commit id of the head.  This is suitable for a "snapshot"
# tarball of an unreleased tree.
#
# src-tarball-release will use "make xenversion" as the version
# number.  This is suitable for release tarballs.
.PHONY: src-tarball-release
src-tarball-release:
	bash ./tools/misc/mktarball $(XEN_ROOT) $$($(MAKE) -C xen xenversion --no-print-directory)

.PHONY: src-tarball
src-tarball:
	bash ./tools/misc/mktarball $(XEN_ROOT) $$(git describe)

.PHONY: clean
clean: $(TARGS_CLEAN)

.PHONY: clean-xen
clean-xen:
	$(MAKE) -C xen clean

.PHONY: clean-tools
clean-tools: clean-tools-public-headers
	$(MAKE) -C tools clean

.PHONY: clean-stubdom
clean-stubdom: clean-tools-public-headers
	$(MAKE) -C stubdom crossclean
ifeq (x86_64,$(XEN_TARGET_ARCH))
	XEN_TARGET_ARCH=x86_32 $(MAKE) -C stubdom crossclean
endif

.PHONY: clean-docs
clean-docs:
	$(MAKE) -C docs clean

# clean, but blow away tarballs
.PHONY: distclean
distclean: $(TARGS_DISTCLEAN)
	rm -rf extras
	$(MAKE) -C tools/include distclean
	rm -f config/Toplevel.mk
	rm -rf dist
	rm -rf config.log config.status config.cache autom4te.cache

.PHONY: distclean-xen
distclean-xen:
	$(MAKE) -C xen distclean

.PHONY: distclean-tools
distclean-tools:
	$(MAKE) -C tools distclean

.PHONY: distclean-stubdom
distclean-stubdom:
	$(MAKE) -C stubdom distclean
ifeq (x86_64,$(XEN_TARGET_ARCH))
	XEN_TARGET_ARCH=x86_32 $(MAKE) -C stubdom distclean
endif

.PHONY: distclean-docs
distclean-docs:
	$(MAKE) -C docs distclean

# Linux name for GNU distclean
.PHONY: mrproper
mrproper: distclean

.PHONY: help
help:
	@echo 'Installation targets:'
	@echo '  install               - build and install everything'
	@echo '  install-xen           - build and install the Xen hypervisor'
	@echo '  install-tools         - build and install the control tools'
	@echo '  install-stubdom       - build and install the stubdomain images'
	@echo '  install-docs          - build and install user documentation'
	@echo ''
	@echo 'Local dist targets:'
	@echo '  dist                  - build and install everything into local dist directory'
	@echo '  world                 - clean everything then make dist'
	@echo '  dist-xen              - build Xen hypervisor and install into local dist'
	@echo '  dist-tools            - build the tools and install into local dist'
	@echo '  dist-stubdom          - build the stubdomain images and install into local dist'
	@echo '  dist-docs             - build user documentation and install into local dist'
	@echo ''
	@echo 'Building targets:'
	@echo '  build                 - build everything'
	@echo '  build-xen             - build Xen hypervisor'
	@echo '  build-tools           - build the tools'
	@echo '  build-stubdom         - build the stubdomain images'
	@echo '  build-docs            - build user documentation'
	@echo ''
	@echo 'Cleaning targets:'
	@echo '  clean                 - clean the Xen, tools and docs'
	@echo '  distclean             - clean plus delete kernel build trees and'
	@echo '                          local downloaded files'
	@echo '  subtree-force-update  - Call *-force-update on all git subtrees (qemu, seabios, ovmf)'
	@echo ''
	@echo 'Miscellaneous targets:'
	@echo '  uninstall             - attempt to remove installed Xen tools'
	@echo '                          (use with extreme care!)'
	@echo
	@echo 'Package targets:'
	@echo '  src-tarball-release   - make a source tarball with xen and qemu tagged with a release'
	@echo '  src-tarball           - make a source tarball with xen and qemu tagged with git describe'
	@echo
	@echo 'Environment:'
	@echo '  [ this documentation is sadly not complete ]'

# Use this target with extreme care!

.PHONY: uninstall-xen
uninstall-xen:
	$(MAKE) -C xen uninstall

.PHONY: uninstall-tools
uninstall-tools:
	$(MAKE) -C tools uninstall

.PHONY: uninstall-stubdom
uninstall-stubdom:
	$(MAKE) -C stubdom uninstall

.PHONY: uninstall-docs
uninstall-docs:
	$(MAKE) -C docs uninstall

.PHONY: uninstall
uninstall: D=$(DESTDIR)
uninstall: uninstall-tools-public-headers $(TARGS_UNINSTALL)

.PHONY: xenversion
xenversion:
	@$(MAKE) --no-print-directory -C xen xenversion

.PHONY: FORCE
FORCE:
