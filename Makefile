#
# Grand Unified Makefile for Xen.
#

DIST_DIR    ?= $(shell pwd)/dist
INSTALL_DIR ?= $(DIST_DIR)/install

SOURCEFORGE_MIRROR := http://heanet.dl.sourceforge.net/sourceforge
#http://voxel.dl.sourceforge.net/sourceforge/
#http://easynews.dl.sourceforge.net/sourceforge

#KERNELS ?= mk.linux-2.6-xen0 mk.linux-2.6-xenU mk.linux-2.4-xen0 mk.linux-2.4-xenU mk.netbsd-2.0-xenU
KERNELS ?= mk.linux-2.6-xen0 mk.linux-2.6-xenU

ALLKERNELS = $(patsubst buildconfigs/%,%,$(wildcard buildconfigs/mk.*))
ALLSPARSETREES = $(patsubst %-xen-sparse,%,$(wildcard *-xen-sparse))

export INSTALL_DIR SOURCEFORGE_MIRROR

.PHONY:	all dist install xen tools kernels docs world clean mkpatches mrproper
.PHONY:	kbuild kdelete kclean

all: 	dist

# build and install everything into local dist directory
dist:	xen tools kernels docs
	install -m0644 ./COPYING $(DIST_DIR)
	install -m0644 ./README $(DIST_DIR)
	install -m0755 ./install.sh $(DIST_DIR)

# install everything into the standard system directories
# NB: install explicitly does not check that everything is up to date!
install: 
	$(MAKE) -C xen install
	$(MAKE) -C tools install
	$(shell cp -a install/boot/* /boot/)
	$(shell cp -a install/lib/modules/* /lib/modules/)
	sh ./docs/check_pkgs && $(MAKE) -C docs install || true
	$(shell cp -dR $(INSTALL_DIR)/boot/*$(LINUX_VER)* $(prefix)/boot/)
	$(shell cp -dR $(INSTALL_DIR)/lib/modules/* $(prefix)/lib/modules/)

xen:
	$(MAKE) prefix=$(INSTALL_DIR) dist=yes -C xen install

tools:
	$(MAKE) prefix=$(INSTALL_DIR) dist=yes -C tools install

# Build all the various kernels and modules
kernels:
	for i in $(KERNELS) ; do $(MAKE) -f buildconfigs/$$i build ; done

docs:
	sh ./docs/check_pkgs && \
		$(MAKE) prefix=$(INSTALL_DIR) dist=yes -C docs install || true

kbuild: kernels

# Delete the kernel build trees entirely
kdelete:
	for i in $(KERNELS) ; do $(MAKE) -f buildconfigs/$$i delete ; done

# Clean the kernel build trees
kclean:
	for i in $(KERNELS) ; do $(MAKE) -f buildconfigs/$$i clean ; done

# Make patches from kernel sparse trees
mkpatches:
	for i in $(ALLSPARSETREES) ; do $(MAKE) -f buildconfigs/Rules.mk $$i-xen.patch ; done


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
	rm -rf dist patches
	for i in $(ALLKERNELS) ; do $(MAKE) -f buildconfigs/$$i delete ; done
	for i in $(ALLSPARSETREES) ; do $(MAKE) -f buildconfigs/Rules.mk $$i-mrproper ; done

install-twisted:
	wget http://www.twistedmatrix.com/products/get-current.epy
	tar -zxf Twisted-*.tar.gz
	( cd Twisted-* ; python setup.py install )

install-logging: LOGGING=logging-0.4.9.2
install-logging:
	[ -f $(LOGGING).tar.gz ] || wget http://www.red-dove.com/$(LOGGING).tar.gz
	tar -zxf $(LOGGING).tar.gz
	( cd $(LOGGING) && python setup.py install )

# handy target to upgrade iptables (use rpm or apt-get in preference)
install-iptables:
	wget http://www.netfilter.org/files/iptables-1.2.11.tar.bz2
	tar -jxf iptables-*.tar.bz2
	( cd iptables-* ; \
	  make PREFIX= KERNEL_DIR=../linux-$(LINUX_VER)-xen0 install)

# Use this target with extreme care!
uninstall:
	cp -a /etc/xen /etc/xen.old && rm -rf /etc/xen 
	rm -rf "/usr/lib/python2.?/site-packages/xen* /usr/lib/libxc* /usr/lib/python2.?/site-packages/Xc*"

# Legacy target for compatibility
linux24:
	$(MAKE) -f buildconfigs/mk.linux-2.4-xen0 build
	$(MAKE) -f buildconfigs/mk.linux-2.4-xenU build

# Legacy target for compatibility
linux26:
	$(MAKE) -f buildconfigs/mk.linux-2.6-xen0 build
	$(MAKE) -f buildconfigs/mk.linux-2.6-xenU build

# Legacy target for compatibility
netbsd20:
	$(MAKE) -f buildconfigs/mk.netbsd-2.0-xenU build
