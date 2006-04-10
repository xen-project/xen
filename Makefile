#
# Grand Unified Makefile for Xen.
#

KERNELS ?= linux-2.6-xen
# You may use wildcards in the above e.g. KERNELS=*2.6*

XKERNELS := $(foreach kernel, $(KERNELS), $(patsubst buildconfigs/mk.%,%,$(wildcard buildconfigs/mk.$(kernel))) )

# Export target architecture overrides to Xen and Linux sub-trees.
ifneq ($(XEN_TARGET_ARCH),)
SUBARCH := $(subst x86_32,i386,$(XEN_TARGET_ARCH))
export XEN_TARGET_ARCH SUBARCH XEN_SYSTYPE
endif

# Default target must appear before any include lines
all: dist

XEN_ROOT=$(CURDIR)
include Config.mk
include buildconfigs/Rules.mk

ifeq ($(XEN_TARGET_X86_PAE),y)
export pae=y
endif

.PHONY:	all dist install xen kernels tools dev-docs docs world clean
.PHONY:	mkpatches mrproper kbuild kdelete kclean

# build and install everything into the standard system directories
install: install-xen install-kernels install-tools install-docs

build: kernels
	$(MAKE) -C xen build
	$(MAKE) -C tools build
	$(MAKE) -C docs build

# The test target is for unit tests that can run without an installation.  Of
# course, many tests require a machine running Xen itself, and these are
# handled elsewhere.
test:
	$(MAKE) -C tools/python test

# build and install everything into local dist directory
dist: DESTDIR=$(DISTDIR)/install
dist: dist-xen dist-kernels dist-tools dist-docs
	$(INSTALL_DIR) $(DISTDIR)/check
	$(INSTALL_DATA) ./COPYING $(DISTDIR)
	$(INSTALL_DATA) ./README $(DISTDIR)
	$(INSTALL_PROG) ./install.sh $(DISTDIR)
	$(INSTALL_PROG) tools/check/chk tools/check/check_* $(DISTDIR)/check
dist-%: DESTDIR=$(DISTDIR)/install
dist-%: install-%
	@: # do nothing

# Legacy dist targets
xen: dist-xen
tools: dist-tools
kernels: dist-kernels
docs: dist-docs

prep-kernels:
	for i in $(XKERNELS) ; do $(MAKE) $$i-prep || exit 1; done

install-xen:
	$(MAKE) -C xen install

install-tools:
	$(MAKE) -C tools install

install-kernels:
	for i in $(XKERNELS) ; do $(MAKE) $$i-install || exit 1; done

install-docs:
	sh ./docs/check_pkgs && $(MAKE) -C docs install || true

dev-docs:
	$(MAKE) -C docs dev-docs

# Build all the various kernels and modules
kbuild: kernels

# Delete the kernel build trees entirely
kdelete:
	for i in $(XKERNELS) ; do $(MAKE) $$i-delete ; done

# Clean the kernel build trees
kclean:
	for i in $(XKERNELS) ; do $(MAKE) $$i-clean ; done

# Make patches from kernel sparse trees
mkpatches:
	for i in $(ALLSPARSETREES) ; do $(MAKE) $$i-xen.patch; done

# build xen, the tools, and a domain 0 plus unprivileged linux-xen images,
# and place them in the install directory. 'make install' should then
# copy them to the normal system directories
world: 
	$(MAKE) clean
	$(MAKE) kdelete
	$(MAKE) dist

# clean doesn't do a kclean
clean:: 
	$(MAKE) -C xen clean
	$(MAKE) -C tools clean
	$(MAKE) -C docs clean

# clean, but blow away kernel build tree plus tarballs
distclean: clean
	rm -rf dist patches/tmp
	for i in $(ALLKERNELS) ; do $(MAKE) $$i-delete ; done
	for i in $(ALLSPARSETREES) ; do $(MAKE) $$i-mrproper ; done

# Linux name for GNU distclean
mrproper: distclean

help:
	@echo 'Installation targets:'
	@echo '  install          - build and install everything'
	@echo '  install-xen      - build and install the Xen hypervisor'
	@echo '  install-tools    - build and install the control tools'
	@echo '  install-kernels  - build and install guest kernels'
	@echo '  install-docs     - build and install user documentation'
	@echo ''
	@echo 'Building targets:'
	@echo '  dist             - build and install everything into local dist directory'
	@echo '  world            - clean everything, delete guest kernel build'
	@echo '                     trees then make dist'
	@echo '  xen              - build and install Xen hypervisor'
	@echo '  tools            - build and install tools'
	@echo '  kernels          - build and install guest kernels'
	@echo '  kbuild           - synonym for make kernels'
	@echo '  docs             - build and install user documentation'
	@echo '  dev-docs         - build developer-only documentation'
	@echo ''
	@echo 'Cleaning targets:'
	@echo '  clean            - clean the Xen, tools and docs (but not guest kernel trees)'
	@echo '  distclean        - clean plus delete kernel build trees and'
	@echo '                     local downloaded files'
	@echo '  kdelete          - delete guest kernel build trees'
	@echo '  kclean           - clean guest kernel build trees'
	@echo ''
	@echo 'Miscellaneous targets:'
	@echo '  prep-kernels     - prepares kernel directories, does not build'
	@echo '  mkpatches        - make patches against vanilla kernels from'
	@echo '                     sparse trees'
	@echo '  uninstall        - attempt to remove installed Xen tools'
	@echo '                     (use with extreme care!)'
	@echo
	@echo 'Environment:'
	@echo '  XEN_PYTHON_NATIVE_INSTALL=y'
	@echo '                   - native python install or dist'
	@echo '                     install into prefix/lib/python<VERSION>'
	@echo '                     instead of <PREFIX>/lib/python'
	@echo '                     true if set to non-empty value, false otherwise'

# Use this target with extreme care!
uninstall: D=$(DESTDIR)
uninstall:
	[ -d $(D)/etc/xen ] && mv -f $(D)/etc/xen $(D)/etc/xen.old-`date +%s` || true
	rm -rf $(D)/etc/init.d/xend*
	rm -rf $(D)/etc/hotplug/xen-backend.agent
	rm -f  $(D)/etc/udev/rules.d/xen-backend.rules
	rm -f  $(D)/etc/udev/xen-backend.rules
	rm -f  $(D)/etc/sysconfig/xendomains
	rm -rf $(D)/var/run/xen* $(D)/var/lib/xen*
	rm -rf $(D)/boot/*xen*
	rm -rf $(D)/lib/modules/*xen*
	rm -rf $(D)/usr/bin/xen* $(D)/usr/bin/lomount
	rm -rf $(D)/usr/bin/cpuperf-perfcntr $(D)/usr/bin/cpuperf-xen
	rm -rf $(D)/usr/bin/xc_shadow
	rm -rf $(D)/usr/bin/pygrub
	rm -rf $(D)/usr/bin/setsize $(D)/usr/bin/tbctl
	rm -rf $(D)/usr/bin/xsls
	rm -rf $(D)/usr/include/xenctrl.h $(D)/usr/include/xenguest.h
	rm -rf $(D)/usr/include/xs_lib.h $(D)/usr/include/xs.h
	rm -rf $(D)/usr/include/xen
	rm -rf $(D)/usr/$(LIBDIR)/libxenctrl* $(D)/usr/$(LIBDIR)/libxenguest*
	rm -rf $(D)/usr/$(LIBDIR)/libxenstore*
	rm -rf $(D)/usr/$(LIBDIR)/python/xen $(D)/usr/$(LIBDIR)/python/grub
	rm -rf $(D)/usr/$(LIBDIR)/xen/
	rm -rf $(D)/usr/lib/xen/
	rm -rf $(D)/usr/local/sbin/setmask $(D)/usr/local/sbin/xen*
	rm -rf $(D)/usr/sbin/xen* $(D)/usr/sbin/netfix $(D)/usr/sbin/xm
	rm -rf $(D)/usr/share/doc/xen
	rm -rf $(D)/usr/share/xen
	rm -rf $(D)/usr/share/man/man1/xen*
	rm -rf $(D)/usr/share/man/man8/xen*

# Legacy targets for compatibility
linux26:
	$(MAKE) 'KERNELS=linux-2.6*' kernels
