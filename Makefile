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

export XEN_ROOT=$(CURDIR)
include Config.mk

SUBARCH := $(subst x86_32,i386,$(XEN_TARGET_ARCH))
export XEN_TARGET_ARCH SUBARCH
export DESTDIR

# build and install everything into the standard system directories
.PHONY: install
install: $(TARGS_INSTALL)

.PHONY: build
build:
	$(MAKE) -C xen build
	$(MAKE) -C tools build
	$(MAKE) -C stubdom build
ifeq (x86_64,$(XEN_TARGET_ARCH))
	XEN_TARGET_ARCH=x86_32 $(MAKE) -C stubdom pv-grub
endif
	$(MAKE) -C docs build

# The test target is for unit tests that can run without an installation.  Of
# course, many tests require a machine running Xen itself, and these are
# handled elsewhere.
.PHONY: test
test:
	$(MAKE) -C tools/python test

# build and install everything into local dist directory
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

# Legacy dist targets
.PHONY: xen tools stubdom docs
xen: dist-xen
tools: dist-tools
stubdom: dist-stubdom
docs: dist-docs

.PHONY: install-xen
install-xen:
	$(MAKE) -C xen install

.PHONY: install-tools
install-tools:
	$(MAKE) -C tools install

.PHONY: install-stubdom
install-stubdom: install-tools
	$(MAKE) -C stubdom install
ifeq (x86_64,$(XEN_TARGET_ARCH))
	XEN_TARGET_ARCH=x86_32 $(MAKE) -C stubdom install-grub
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
subtree-force-update:
	$(MAKE) -C tools subtree-force-update

.PHONY: subtree-force-update-all
subtree-force-update-all:
	$(MAKE) -C tools subtree-force-update-all

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
src-tarball-release: subtree-force-update-all
	bash ./tools/misc/mktarball $(XEN_ROOT) $$($(MAKE) -C xen xenversion --no-print-directory)

.PHONY: src-tarball
src-tarball: subtree-force-update-all
	bash ./tools/misc/mktarball $(XEN_ROOT) $$(git describe)

.PHONY: clean
clean::
	$(MAKE) -C xen clean
	$(MAKE) -C tools clean
	$(MAKE) -C stubdom crossclean
ifeq (x86_64,$(XEN_TARGET_ARCH))
	XEN_TARGET_ARCH=x86_32 $(MAKE) -C stubdom crossclean
endif
	$(MAKE) -C docs clean

# clean, but blow away tarballs
.PHONY: distclean
distclean:
	rm -f config/Toplevel.mk
	$(MAKE) -C xen distclean
	$(MAKE) -C tools distclean
	$(MAKE) -C stubdom distclean
ifeq (x86_64,$(XEN_TARGET_ARCH))
	XEN_TARGET_ARCH=x86_32 $(MAKE) -C stubdom distclean
endif
	$(MAKE) -C docs distclean
	rm -rf dist
	rm -rf config.log config.status config.cache autom4te.cache

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
	@echo 'Building targets:'
	@echo '  dist                  - build and install everything into local dist directory'
	@echo '  world                 - clean everything then make dist'
	@echo '  xen                   - build and install Xen hypervisor'
	@echo '  tools                 - build and install tools'
	@echo '  stubdom               - build and install the stubdomain images'
	@echo '  docs                  - build and install user documentation'
	@echo ''
	@echo 'Cleaning targets:'
	@echo '  clean                 - clean the Xen, tools and docs (but not guest kernel trees)'
	@echo '  distclean             - clean plus delete kernel build trees and'
	@echo '                          local downloaded files'
	@echo '  subtree-force-update  - Call *-force-update on all git subtrees (qemu, seabios, ovmf)'
	@echo ''
	@echo 'Miscellaneous targets:'
	@echo '  uninstall             - attempt to remove installed Xen tools'
	@echo '                          (use with extreme care!)'
	@echo
	@echo 'Trusted Boot (tboot) targets:'
	@echo '  build-tboot           - download and build the tboot module'
	@echo '  install-tboot         - download, build, and install the tboot module'
	@echo '  clean-tboot           - clean the tboot module if it exists'
	@echo
	@echo 'Package targets:'
	@echo '  src-tarball-release   - make a source tarball with xen and qemu tagged with a release'
	@echo '  src-tarball           - make a source tarball with xen and qemu tagged with git describe'
	@echo
	@echo 'Environment:'
	@echo '  [ this documentation is sadly not complete ]'

# Use this target with extreme care!
.PHONY: uninstall
uninstall: D=$(DESTDIR)
uninstall:
	$(MAKE) -C xen uninstall
	make -C tools uninstall
	rm -rf $(D)/boot/tboot*

.PHONY: xenversion
xenversion:
	@$(MAKE) --no-print-directory -C xen xenversion

#
# tboot targets
#

TBOOT_TARFILE = tboot-20090330.tar.gz
#TBOOT_BASE_URL = http://downloads.sourceforge.net/tboot
TBOOT_BASE_URL = $(XEN_EXTFILES_URL)

.PHONY: build-tboot
build-tboot: download_tboot
	$(MAKE) -C tboot build

.PHONY: install-tboot
install-tboot: download_tboot
	$(MAKE) -C tboot install

.PHONY: dist-tboot
dist-tboot: download_tboot
	$(MAKE) DESTDIR=$(DISTDIR)/install -C tboot dist

.PHONY: clean-tboot
clean-tboot:
	[ ! -d tboot ] || $(MAKE) -C tboot clean

.PHONY: distclean-tboot
distclean-tboot:
	[ ! -d tboot ] || $(MAKE) -C tboot distclean

.PHONY: download_tboot
download_tboot: tboot/Makefile

tboot/Makefile: tboot/$(TBOOT_TARFILE)
	[ -e tboot/Makefile ] || tar -xzf tboot/$(TBOOT_TARFILE) -C tboot/ --strip-components 1

tboot/$(TBOOT_TARFILE):
	mkdir -p tboot
	wget -O tboot/$(TBOOT_TARFILE) $(TBOOT_BASE_URL)/$(TBOOT_TARFILE)
