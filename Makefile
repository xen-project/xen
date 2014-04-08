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

ifeq ($(CONFIG_QEMU_TRAD),y)
QEMU_TRAD_DIR_TGT := tools/qemu-xen-traditional-dir

tools/qemu-xen-traditional-dir:
	$(MAKE) -C tools qemu-xen-traditional-dir-find

.PHONY: tools/qemu-xen-traditional-dir-force-update
tools/qemu-xen-traditional-dir-force-update:
	$(MAKE) -C tools qemu-xen-traditional-dir-force-update
endif

ifeq ($(CONFIG_QEMU_XEN),y)
QEMU_XEN_DIR_TGT := tools/qemu-xen-dir

tools/qemu-xen-dir:
	$(MAKE) -C tools qemu-xen-dir-find

.PHONY: tools/qemu-xen-dir-force-update
tools/qemu-xen-dir-force-update:
	$(MAKE) -C tools qemu-xen-dir-force-update
endif

.PHONY: install-tools
install-tools: $(QEMU_TRAD_DIR_TARGET) $(QEMU_XEN_DIR_TARGET)
	$(MAKE) -C tools install

.PHONY: install-stubdom
install-stubdom: $(QEMU_TRAD_DIR_TARGET) install-tools
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

.PHONY: dev-docs
dev-docs:
	$(MAKE) -C docs dev-docs

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

# Prepare for source tarball
.PHONY: src-tarball
src-tarball: distclean
	$(MAKE) -C xen .banner
	rm -rf xen/tools/figlet .[a-z]*
	$(MAKE) -C xen distclean

.PHONY: help
help:
	@echo 'Installation targets:'
	@echo '  install          - build and install everything'
	@echo '  install-xen      - build and install the Xen hypervisor'
	@echo '  install-tools    - build and install the control tools'
	@echo '  install-stubdom  - build and install the stubdomain images'
	@echo '  install-docs     - build and install user documentation'
	@echo ''
	@echo 'Building targets:'
	@echo '  dist             - build and install everything into local dist directory'
	@echo '  world            - clean everything then make dist'
	@echo '  xen              - build and install Xen hypervisor'
	@echo '  tools            - build and install tools'
	@echo '  stubdom          - build and install the stubdomain images'
	@echo '  docs             - build and install user documentation'
	@echo '  dev-docs         - build developer-only documentation'
	@echo ''
	@echo 'Cleaning targets:'
	@echo '  clean            - clean the Xen, tools and docs (but not guest kernel trees)'
	@echo '  distclean        - clean plus delete kernel build trees and'
	@echo '                     local downloaded files'
	@echo ''
	@echo 'Miscellaneous targets:'
	@echo '  uninstall        - attempt to remove installed Xen tools'
	@echo '                     (use with extreme care!)'
	@echo
	@echo 'Trusted Boot (tboot) targets:'
	@echo '  build-tboot      - download and build the tboot module'
	@echo '  install-tboot    - download, build, and install the tboot module'
	@echo '  clean-tboot      - clean the tboot module if it exists'
	@echo
	@echo 'Environment:'
	@echo '  [ this documentation is sadly not complete ]'

# Use this target with extreme care!
.PHONY: uninstall
uninstall: D=$(DESTDIR)
uninstall:
	[ -d $(D)$(XEN_CONFIG_DIR) ] && mv -f $(D)$(XEN_CONFIG_DIR) $(D)$(XEN_CONFIG_DIR).old-`date +%s` || true
	$(MAKE) -C xen uninstall
	rm -rf $(D)$(CONFIG_DIR)/init.d/xendomains $(D)$(CONFIG_DIR)/init.d/xend
	rm -rf $(D)$(CONFIG_DIR)/init.d/xencommons $(D)$(CONFIG_DIR)/init.d/xen-watchdog
	rm -f  $(D)$(CONFIG_DIR)/udev/rules.d/xen-backend.rules
	rm -f  $(D)$(CONFIG_DIR)/udev/rules.d/xend.rules
	rm -f  $(D)$(SYSCONFIG_DIR)/xendomains
	rm -f  $(D)$(SYSCONFIG_DIR)/xencommons
	rm -rf $(D)/var/run/xen* $(D)/var/lib/xen*
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
