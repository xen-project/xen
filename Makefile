#
# Grand Unified Makefile for Xen.
#

INSTALL_DIR ?= $(shell pwd)/install

SOURCEFORGE_MIRROR := http://heanet.dl.sourceforge.net/sourceforge
#http://voxel.dl.sourceforge.net/sourceforge/
#http://easynews.dl.sourceforge.net/sourceforge

.PHONY: docs delete-symlinks clean

# a not partcularly useful but safe default target
all: make-symlinks
	$(MAKE) prefix=$(INSTALL_DIR) dist=yes -C xen install
	$(MAKE) prefix=$(INSTALL_DIR) dist=yes -C tools install

# install everything into the standard system directories
install: dist
	$(MAKE) -C xen install
	$(MAKE) -C tools install
	$(shell cp -a install/boot/*$(LINUX_VER)* /boot/)
	$(shell cp -a install/lib/modules/* /lib/modules/)

# install xen and tools into the install directory
dist: all
	$(MAKE) linux-xenU
	$(MAKE) linux-xen0

LINUX_RELEASE    ?= 2.6
LINUX_VER        ?= $(shell ( /bin/ls -ld linux-$(LINUX_RELEASE).*-xen-sparse ) 2>/dev/null | \
		      sed -e 's!^.*linux-\(.\+\)-xen-sparse!\1!' )
LINUX26_VER      ?= $(shell ( /bin/ls -ld linux-2.6.*-xen-sparse ) 2>/dev/null | \
		      sed -e 's!^.*linux-\(.\+\)-xen-sparse!\1!' )
LINUX_CONFIG_DIR ?= $(INSTALL_DIR)/boot
LINUX_SRC_PATH   ?= .:..
LINUX_SRC        ?= $(firstword $(foreach dir,$(subst :, ,$(LINUX_SRC_PATH)),\
                    $(wildcard $(dir)/linux-$(LINUX_VER).tar.*z*)))

# search for a pristine kernel tar ball, or try downloading one
pristine-linux-src: 
ifeq ($(LINUX_SRC),)
	@echo "Cannot find linux-$(LINUX_VER).tar.gz in path $(LINUX_SRC_PATH)"
	@wget http://www.kernel.org/pub/linux/kernel/v$(LINUX_RELEASE)/linux-$(LINUX_VER).tar.bz2 -O./linux-$(LINUX_VER).tar.bz2
LINUX_SRC := ./linux-$(LINUX_VER).tar.bz2 
endif

patches/ebtables.diff:
	mkdir -p patches
	#wget $(SOURCEFORGE_MIRROR)/ebtables/ebtables-brnf-5_vs_2.4.25.diff.gz \
	     -O- | gunzip -c > $@
	wget http://www.cl.cam.ac.uk/netos/xen/downloads/ebtables-brnf-5_vs_2.4.27.diff.gz -O- | gunzip -c > $@

LINUX_TREES := linux-$(LINUX_VER)-xen0 linux-$(LINUX_VER)-xenU

# make a linux-xen build tree from a pristine kernel plus sparse tree
ifeq ($(LINUX_RELEASE),2.4)
mk-linux-trees: patches/ebtables.diff pristine-linux-src 
	$(RM) -rf $(LINUX_TREES)
	echo $(LINUX_SRC) | grep -q bz2 && \
	    tar -jxf $(LINUX_SRC) || tar -zxf $(LINUX_SRC)
	mv linux-$(LINUX_VER) linux-$(LINUX_VER)-xen0
	( cd linux-$(LINUX_VER)-xen-sparse ; \
          ./mkbuildtree ../linux-$(LINUX_VER)-xen0 )
	cp -al linux-$(LINUX_VER)-xen0 linux-$(LINUX_VER)-xenU
	( cd linux-$(LINUX_VER)-xen0 ; \
          patch -p1 -F3 < ../patches/ebtables.diff ; \
          sed -e 's/^EXTRAVERSION.*/&-xen0/' Makefile >Mk.tmp ; \
          rm -f Makefile ; mv Mk.tmp Makefile )
	( cd linux-$(LINUX_VER)-xenU ; \
          sed -e 's/^EXTRAVERSION.*/&-xenU/' Makefile >Mk.tmp ; \
          rm -f Makefile ; mv Mk.tmp Makefile )
else
mk-linux-trees: pristine-linux-src 
	$(RM) -rf $(LINUX_TREES)
	echo $(LINUX_SRC) | grep -q bz2 && \
	    tar -jxf $(LINUX_SRC) || tar -zxf $(LINUX_SRC)
	mv linux-$(LINUX_VER) linux-$(LINUX_VER)-xen0
	( cd linux-$(LINUX_VER)-xen-sparse ; \
          ./mkbuildtree ../linux-$(LINUX_VER)-xen0 )
	cp -al linux-$(LINUX_VER)-xen0 linux-$(LINUX_VER)-xenU
	( cd linux-$(LINUX_VER)-xen0 ; \
          sed -e 's/^EXTRAVERSION.*/&-xen0/' Makefile >Mk.tmp ; \
          rm -f Makefile ; mv Mk.tmp Makefile )
	( cd linux-$(LINUX_VER)-xenU ; \
          sed -e 's/^EXTRAVERSION.*/&-xenU/' Makefile >Mk.tmp ; \
          rm -f Makefile ; mv Mk.tmp Makefile )
endif

# configure the specified linux tree
CDIR = $(subst config-,linux-$(LINUX_VER)-,$@)
ifeq ($(LINUX_RELEASE),2.4)
config-xen%:
	$(MAKE) -C $(CDIR) ARCH=xen mrproper
	cp $(LINUX_CONFIG_DIR)/config-$(LINUX_VER)$(subst config,,$@) \
	    $(CDIR)/.config || \
	    $(MAKE) -C $(CDIR) ARCH=xen $(subst config-,,$@)_config
	$(MAKE) -C $(CDIR) ARCH=xen oldconfig
	$(MAKE) -C $(CDIR) ARCH=xen dep
else
config-xen%:
	$(MAKE) -C $(CDIR) ARCH=xen mrproper
	@[ -e $(LINUX_CONFIG_DIR)/config-$(LINUX_VER)-$(subst config-,,$@) ] \
	  && cp $(LINUX_CONFIG_DIR)/config-$(LINUX_VER)-$(subst config-,,$@) \
		$(CDIR)/.config || \
	$(MAKE) -C $(CDIR) ARCH=xen $(subst config-,,$@)_defconfig
endif

# build the specified linux tree
BDIR = $(subst linux-,linux-$(LINUX_VER)-,$@)
linux-xen%:	
	$(MAKE) -C $(BDIR) ARCH=xen modules
	$(MAKE) -C $(BDIR) ARCH=xen INSTALL_MOD_PATH=$(INSTALL_DIR) \
	    modules_install
	$(MAKE) -C $(BDIR) ARCH=xen INSTALL_PATH=$(INSTALL_DIR) install

NETBSD_RELEASE   ?= 2.0
NETBSD_VER       ?= $(shell ( /bin/ls -ld netbsd-$(NETBSD_RELEASE)*-xen-sparse ) 2>/dev/null | \
		      sed -e 's!^.*netbsd-\(.\+\)-xen-sparse!\1!' )
NETBSD_CVSSNAP   ?= 20040906
NETBSD_SRC_PATH  ?= .:..
NETBSD_SRC       ?= $(firstword $(foreach dir,$(subst :, ,$(NETBSD_SRC_PATH)),\
                    $(wildcard $(dir)/netbsd-$(NETBSD_VER)-xen-kernel-$(NETBSD_CVSSNAP).tar.*z*)))
NETBSD_TOOLS_SRC ?= $(firstword $(foreach dir,$(subst :, ,$(NETBSD_SRC_PATH)),\
                    $(wildcard $(dir)/netbsd-$(NETBSD_VER)-tools.tar.*z*)))

NETBSD_TREES := netbsd-$(NETBSD_VER)-xenU

pristine-netbsd-src: 
ifeq ($(NETBSD_SRC),)
	@echo "Cannot find netbsd-$(NETBSD_VER)-xen-kernel-$(NETBSD_CVSSNAP).tar.gz in path $(NETBSD_SRC_PATH)"
	@wget http://www.cl.cam.ac.uk/Research/SRG/netos/xen/downloads/netbsd-$(NETBSD_VER)-xen-kernel-$(NETBSD_CVSSNAP).tar.bz2 -O./netbsd-$(NETBSD_VER)-xen-kernel-$(NETBSD_CVSSNAP).tar.bz2
NETBSD_SRC := ./netbsd-$(NETBSD_VER)-xen-kernel-$(NETBSD_CVSSNAP).tar.bz2 
endif

pristine-netbsd-tools-src: 
ifeq ($(NETBSD_TOOLS_SRC),)
	@echo "Cannot find netbsd-$(NETBSD_VER)-tools.tar.gz in path $(NETBSD_SRC_PATH)"
	@wget http://www.cl.cam.ac.uk/Research/SRG/netos/xen/downloads/netbsd-$(NETBSD_VER)-tools.tar.bz2 -O./netbsd-$(NETBSD_VER)-tools.tar.bz2
NETBSD_TOOLS_SRC := ./netbsd-$(NETBSD_VER)-tools.tar.bz2 
endif

netbsd-tools: pristine-netbsd-tools-src
	@[ -d netbsd-$(NETBSD_RELEASE)-tools ] || { \
		echo extract $(NETBSD_TOOLS_SRC); \
		tar -jxf $(NETBSD_TOOLS_SRC); }

mk-netbsd-trees: netbsd-tools pristine-netbsd-src 
	$(RM) -rf $(NETBSD_TREES)
	echo $(NETBSD_SRC) | grep -q bz2 && \
	    tar -jxf $(NETBSD_SRC) || tar -zxf $(NETBSD_SRC)
	mv netbsd-$(NETBSD_VER)-xen-kernel-$(NETBSD_CVSSNAP) \
	    netbsd-$(NETBSD_VER)-xenU
	( cd netbsd-$(NETBSD_VER)-xen-sparse ; \
          ./mkbuildtree ../netbsd-$(NETBSD_VER)-xenU )

# build the specified netbsd tree
NBDIR = $(subst netbsd-,netbsd-$(NETBSD_VER)-,$@)
netbsd-xen%:	
	$(MAKE) -C $(NBDIR) config
	$(MAKE) -C $(NBDIR) netbsd
	$(MAKE) -C $(NBDIR) INSTALL_PATH=$(INSTALL_DIR) INSTALL_NAME=boot/netbsd-$(NETBSD_VER)-$(subst netbsd-,,$@) install

# build xen, the tools, and a domain 0 plus unprivileged linux-xen images,
# and place them in the install directory. 'make install' should then
# copy them to the normal system directories
world:
	$(MAKE) clean
	$(MAKE) all
	$(MAKE) mk-linux-trees
	$(MAKE) config-xenU
	$(MAKE) linux-xenU
	$(MAKE) config-xen0
	$(MAKE) linux-xen0
	$(MAKE) docs

linux26:
	$(MAKE) LINUX_RELEASE=2.6 mk-linux-trees
	$(MAKE) LINUX_RELEASE=2.6 config-xenU
	$(MAKE) LINUX_RELEASE=2.6 linux-xenU
	$(MAKE) LINUX_RELEASE=2.6 config-xen0
	$(MAKE) LINUX_RELEASE=2.6 linux-xen0

linux24:
	$(MAKE) LINUX_RELEASE=2.4 mk-linux-trees
	$(MAKE) LINUX_RELEASE=2.4 config-xenU
	$(MAKE) LINUX_RELEASE=2.4 linux-xenU
	$(MAKE) LINUX_RELEASE=2.4 config-xen0
	$(MAKE) LINUX_RELEASE=2.4 linux-xen0

netbsd:
	$(MAKE) mk-netbsd-trees
	$(MAKE) netbsd-xenU

clean: delete-symlinks
	$(MAKE) -C xen clean
	$(MAKE) -C tools clean
	$(MAKE) -C docs clean

# clean, but blow away linux build tree plus src tar ball
mrproper: clean
	rm -rf install/* patches $(LINUX_TREES) linux-$(LINUX_VER).tar.*

make-symlinks: delete-symlinks
	ln -sf linux-$(LINUX26_VER)-xen-sparse linux-xen-sparse

delete-symlinks:
	$(RM) linux-xen-sparse

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

uninstall:
	cp -a /etc/xen /etc/xen.old && rm -rf /etc/xen 
	rm -rf "/usr/lib/python2.2/site-packages/xen* /usr/lib/libxc* /usr/lib/python2.2/site-packages/Xc*"

docs:
	$(MAKE) -C docs all || true
