#
# Grand Unified Makefile for Xen.
#

INSTALL_DIR ?= $(shell pwd)/install

SOURCEFORGE_MIRROR = http://heanet.dl.sourceforge.net/sourceforge
#http://voxel.dl.sourceforge.net/sourceforge/
#http://easynews.dl.sourceforge.net/sourceforge

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

LINUX_VER        ?= $(shell ( /bin/ls -ld linux-*-xen-sparse ) 2>/dev/null | sed -e 's!^.*linux-\(.\+\)-xen-sparse!\1!' )
LINUX_CONFIG_DIR ?= $(INSTALL_DIR)/boot
LINUX_SRC_PATH   ?= .:..
LINUX_SRC_X ?= $(firstword $(foreach dir,$(subst :, ,$(LINUX_SRC_PATH)),$(wildcard $(dir)/linux-$(LINUX_VER).tar.*z*)))

# search for a pristine kernel tar ball, or try downloading one
pristine-linux-src: 
ifneq ($(LINUX_SRC),)
	@[ -r "$(LINUX_SRC)" ] || (echo "Can not find linux src at $(LINUX_SRC)" && false)
LINUX_SRC_X = $(LINUX_SRC)
else 
ifeq ($(LINUX_SRC_X),)
	@echo "Can not find linux-$(LINUX_VER).tar.gz in path $(LINUX_SRC_PATH)"
	@wget ftp://ftp.kernel.org/pub/linux/kernel/v2.4/linux-$(LINUX_VER).tar.bz2 -O./linux-$(LINUX_VER).tar.bz2
LINUX_SRC_X = ./linux-$(LINUX_VER).tar.bz2 
endif
endif

patches/ebtables-brnf-5_vs_2.4.25.diff:
	mkdir -p patches
	wget $(SOURCEFORGE_MIRROR)/ebtables/ebtables-brnf-5_vs_2.4.25.diff.gz -O- | gunzip -c > $@

LINUX_TREES = linux-$(LINUX_VER)-xen0 linux-$(LINUX_VER)-xenU

# make a linux-xen build tree from a pristine kernel plus sparse tree
mk-linux-trees: patches/ebtables-brnf-5_vs_2.4.25.diff pristine-linux-src 
	$(RM) -rf $(LINUX_TREES)
ifeq (,$(findstring bz2,$(LINUX_SRC_X)))
	tar -zxf $(LINUX_SRC_X)
else
	tar -jxf $(LINUX_SRC_X)
endif
	mv linux-$(LINUX_VER) linux-$(LINUX_VER)-xen0
	( cd linux-$(LINUX_VER)-xen-sparse ; ./mkbuildtree ../linux-$(LINUX_VER)-xen0 )
	cp -al linux-$(LINUX_VER)-xen0 linux-$(LINUX_VER)-xenU
	(cd linux-$(LINUX_VER)-xen0 && patch -p1 -F3 < ../patches/ebtables-brnf-5_vs_2.4.25.diff)

# configure the specified linux tree
config-xen%:
	$(MAKE) -C $(subst config-,linux-$(LINUX_VER)-,$(@)) ARCH=xen mrproper
	cp $(LINUX_CONFIG_DIR)/config-$(LINUX_VER)-$(subst config-,,$(@)) $(subst config-,linux-$(LINUX_VER)-,$(@))/.config || $(MAKE) -C $(subst config-,linux-$(LINUX_VER)-,$(@)) ARCH=xen $(subst config-,,$(@))_config
	$(MAKE) -C $(subst config-,linux-$(LINUX_VER)-,$(@)) ARCH=xen oldconfig
	$(MAKE) -C $(subst config-,linux-$(LINUX_VER)-,$(@)) ARCH=xen dep

# build the specified linux tree
linux-xen%:	
	$(MAKE) -C $(subst linux-,linux-$(LINUX_VER)-,$(@)) ARCH=xen modules
	$(MAKE) -C $(subst linux-,linux-$(LINUX_VER)-,$(@)) ARCH=xen INSTALL_MOD_PATH=$(INSTALL_DIR) modules_install
	$(MAKE) -C $(subst linux-,linux-$(LINUX_VER)-,$(@)) ARCH=xen INSTALL_PATH=$(INSTALL_DIR) install	

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


clean: delete-symlinks
	$(MAKE) -C xen clean
	$(MAKE) -C tools clean

# clean, but blow away linux build tree plus src tar ball
mrproper: clean
	rm -rf install/* patches $(LINUX_TREES) linux-$(LINUX_VER).tar.*


make-symlinks: delete-symlinks
	ln -sf linux-$(LINUX_VER)-xen-sparse linux-xen-sparse

delete-symlinks:
	$(RM) linux-xen-sparse

# handy target to install twisted (use rpm or apt-get in preference)
install-twisted:
	wget http://www.twistedmatrix.com/products/get-current.epy
	tar -zxf Twisted-*.tar.gz
	(cd Twisted-* ; python setup.py install)

# handy target to upgrade iptables (use rpm or apt-get in preference)
install-iptables:
	wget http://www.netfilter.org/files/iptables-1.2.11.tar.bz2
	tar -jxf iptables-*.tar.bz2
	(cd iptables-* ; make PREFIX= KERNEL_DIR=../linux-$(LINUX_VER)-xen0 install)


