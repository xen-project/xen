#
# Grand Unified Makefile for Xen.
#

INSTALL_DIR ?= $(shell pwd)/install

SOURCEFORGE_MIRROR := http://heanet.dl.sourceforge.net/sourceforge
#http://voxel.dl.sourceforge.net/sourceforge/
#http://easynews.dl.sourceforge.net/sourceforge

#KERNELS = linux-2.6-xen0 linux-2.6-xenU linux-2.4-xen0 linux-2.4-xenU netbsd-2.0-xenU
KERNELS = linux-2.6-xen0 linux-2.6-xenU

export INSTALL_DIR SOURCEFORGE_MIRROR

.PHONY: all dist install kernels kdelete mkpatches world docs clean mrproper

all: 
	$(MAKE) prefix=$(INSTALL_DIR) dist=yes -C xen install
	$(MAKE) prefix=$(INSTALL_DIR) dist=yes -C tools install
	$(MAKE) kernels

# install xen and tools into the install directory
dist: all


# install everything into the standard system directories
# NB: install explicitly does not check that everything is up to date!
install: 
	$(MAKE) -C xen install
	$(MAKE) -C tools install
	$(shell cp -a install/boot/* /boot/)
	$(shell cp -a install/lib/modules/* /lib/modules/)

# Build all the various kernels
kernels:
	for i in $(KERNELS) ; do $(MAKE) -f buildconfigs/$$i build ; done

# Delete the kernel build trees
kdelete:
	for i in $(KERNELS) ; do $(MAKE) -f buildconfigs/$$i kdelete ; done

# Make patches from kernel sparse trees
mkpatches:
	$(MAKE) -f buildconfigs/Rules.mk mkpatches


# build xen, the tools, and a domain 0 plus unprivileged linux-xen images,
# and place them in the install directory. 'make install' should then
# copy them to the normal system directories
world:
	$(MAKE) clean
	$(MAKE) kdelete
	$(MAKE) all
	$(MAKE) docs

docs:
	$(MAKE) -C docs all || true

clean: 
	$(MAKE) -C xen clean
	$(MAKE) -C tools clean
	$(MAKE) -C docs clean

# clean, but blow away kernel build tree plus tar balls
mrproper: clean
	rm -rf install/* patches *.tar.bz2 
	for i in `ls buildconfigs | grep -v Rules.mk` ; do $(MAKE) -f buildconfigs/$$i kdelete || true ; done
	$(MAKE) -f buildconfigs/Rules.mk mrproper

# handy target to install twisted (use rpm or apt-get in preference)
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
	$(MAKE) -f buildconfigs/linux-2.4-xen0
	$(MAKE) -f buildconfigs/linux-2.4-xenU

# Legacy target for compatibility
linux26:
	$(MAKE) -f buildconfigs/linux-2.6-xen0
	$(MAKE) -f buildconfigs/linux-2.6-xenU

