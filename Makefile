#
# Grand Unified Makefile for Xen.
#

DIST_DIR	:= $(CURDIR)/dist
DESTDIR		:= $(DIST_DIR)/install

INSTALL		:= install
INSTALL_DIR	:= $(INSTALL) -d -m0755
INSTALL_DATA	:= $(INSTALL) -m0644
INSTALL_PROG	:= $(INSTALL) -m0755

KERNELS ?= linux-2.6-xen0 linux-2.6-xenU
# linux-2.4-xen0 linux-2.4-xenU netbsd-2.0-xenU
# You may use wildcards in the above e.g. KERNELS=*2.4*

ALLKERNELS = $(patsubst buildconfigs/mk.%,%,$(wildcard buildconfigs/mk.*))
ALLSPARSETREES = $(patsubst %-xen-sparse,%,$(wildcard *-xen-sparse))
XKERNELS := $(foreach kernel, $(KERNELS), $(patsubst buildconfigs/mk.%,%,$(wildcard buildconfigs/mk.$(kernel))) )


export DESTDIR

include buildconfigs/Rules.mk

.PHONY:	all dist install xen tools kernels docs world clean mkpatches mrproper
.PHONY:	kbuild kdelete kclean install-tools install-xen install-docs
.PHONY: install-kernels

all: dist

# install everything into the standard system directories
# NB: install explicitly does not check that everything is up to date!
install: install-tools install-xen install-kernels install-docs

install-xen:
	$(MAKE) -C xen install

install-tools:
	$(MAKE) -C tools install

install-kernels:
	cp -a $(INSTALL_DIR)/boot/* /boot/
	cp -a $(INSTALL_DIR)/lib/modules/* /lib/modules/
	cp -dR $(INSTALL_DIR)/boot/*$(LINUX_VER)* $(prefix)/boot/
	cp -dR $(INSTALL_DIR)/lib/modules/* $(prefix)/lib/modules/

install-docs:
	sh ./docs/check_pkgs && $(MAKE) -C docs install || true
	sh ./docs/check_pkgs
	-$(MAKE) -C docs install

# build and install everything into local dist directory
dist: xen tools kernels docs
	$(INSTALL_DIR) $(DIST_DIR)/check
	$(INSTALL_DATA) ./COPYING $(DIST_DIR)
	$(INSTALL_DATA) ./README $(DIST_DIR)
	$(INSTALL_PROG) ./install.sh $(DIST_DIR)
	$(INSTALL_PROG) tools/check/chk tools/check/check_* $(DIST_DIR)/check

xen:
	$(MAKE) dist=yes -C xen install

tools:
	$(MAKE) dist=yes -C tools install

kernels:
	for i in $(XKERNELS) ; do $(MAKE) $$i-build || exit 1; done

docs:
	sh ./docs/check_pkgs
	-$(MAKE) dist=yes -C docs install

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
	for i in $(ALLSPARSETREES) ; do $(MAKE) $$i-xen.patch || exit 1; done


# build xen, the tools, and a domain 0 plus unprivileged linux-xen images,
# and place them in the install directory. 'make install' should then
# copy them to the normal system directories
world: 
	$(MAKE) clean
	$(MAKE) kdelete
	$(MAKE) dist

# clean doesn't do a kclean
clean: 
	$(MAKE) -C xen clean
	$(MAKE) -C tools clean
	$(MAKE) -C docs clean

# clean, but blow away kernel build tree plus tar balls
mrproper: clean
	rm -rf dist patches/tmp
	for i in $(ALLKERNELS) ; do $(MAKE) $$i-delete ; done
	for i in $(ALLSPARSETREES) ; do $(MAKE) $$i-mrproper ; done

install-twisted:
	wget http://www.twistedmatrix.com/products/get-current.epy
	tar -zxf Twisted-*.tar.gz
	cd Twisted-* && python setup.py install

install-logging: LOGGING=logging-0.4.9.2
install-logging:
	[ -f $(LOGGING).tar.gz ] || wget http://www.red-dove.com/$(LOGGING).tar.gz
	tar -zxf $(LOGGING).tar.gz
	cd $(LOGGING) && python setup.py install

# handy target to upgrade iptables (use rpm or apt-get in preference)
install-iptables:
	wget http://www.netfilter.org/files/iptables-1.2.11.tar.bz2
	tar -jxf iptables-1.2.11.tar.bz2
	$(MAKE) -C iptables-1.2.11 PREFIX= KERNEL_DIR=../linux-$(LINUX_VER)-xen0 install

help:
	@echo 'Installation targets:'
	@echo '  install          - install everything'
	@echo '  install-xen      - install the Xen hypervisor'
	@echo '  install-tools    - install the control tools'
	@echo '  install-kernels  - install guest kernels'
	@echo '  install-docs     - install documentation'
	@echo ''
	@echo 'Building targets:'
	@echo '  dist             - build everything and place in dist/'
	@echo '  world            - clean everything, delete guest kernel build'
	@echo '                     trees then make dist'
	@echo '  xen              - build Xen hypervisor and place in dist/'
	@echo '  tools            - build tools and place in dist/'
	@echo '  kernels          - build guest kernels and place in dist/'
	@echo '  kbuild           - synonym for make kernels'
	@echo '  docs             - build docs and place in dist/'
	@echo ''
	@echo 'Cleaning targets:'
	@echo '  clean            - clean the Xen, tools and docs (but not'
	@echo '                     guest kernel) trees'
	@echo '  mrproper         - clean plus delete kernel tarballs and kernel'
	@echo '                     build trees'
	@echo '  kdelete          - delete guest kernel build trees'
	@echo '  kclean           - clean guest kernel build trees'
	@echo ''
	@echo 'Dependency installation targets:'
	@echo '  install-twisted  - install the Twisted Matrix Framework'
	@echo '  install-logging  - install the Python Logging package'
	@echo '  install-iptables - install iptables tools'
	@echo ''
	@echo 'Miscellaneous targets:'
	@echo '  mkpatches        - make patches against vanilla kernels from'
	@echo '                     sparse trees'
	@echo '  uninstall        - attempt to remove installed Xen tools (use'
	@echo '                     with extreme care!)'

# Use this target with extreme care!
uninstall:
	cp -a /etc/xen /etc/xen.old && rm -rf /etc/xen 
	rm -rf "/usr/lib/python2.?/site-packages/xen* /usr/lib/libxc* /usr/lib/python2.?/site-packages/Xc*"

# Legacy targets for compatibility
linux24:
	$(MAKE) linux-2.4-xen0-build
	$(MAKE) linux-2.4-xenU-build

linux26:
	$(MAKE) linux-2.6-xen0-build
	$(MAKE) linux-2.6-xenU-build

netbsd20:
	$(MAKE) netbsd-2.0-xenU-build
