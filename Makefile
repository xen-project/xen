#
# Grand Unified Makefile for Xen.
#

INSTALL_DIR ?= $(shell pwd)/install

all: make-symlinks
	$(MAKE) -C xen
	$(MAKE) -C tools

install: all
	$(MAKE) -C xen install
	$(MAKE) -C tools install
	$(shell cp -a install/boot/*$(LINUX_VER)* /boot/)

dist: all
	$(MAKE) prefix=$(INSTALL_DIR) dist=yes -C xen install
	$(MAKE) prefix=$(INSTALL_DIR) dist=yes -C tools install

LINUX_VER        ?= $(shell ( /bin/ls -ld linux-*-xen-sparse ) 2>/dev/null | sed -e 's!^.*linux-\(.\+\)-xen-sparse!\1!' )
LINUX_SRC        ?= linux-$(LINUX_VER).tar.gz
LINUX_CONFIG_DIR ?= $(INSTALL_DIR)/boot

pristine-linux-src:
	[ -e $(LINUX_SRC) ] || wget ftp://ftp.kernel.org/pub/linux/kernel/v2.4/linux-$(LINUX_VER).tar.gz -O- > $(LINUX_SRC)

linux-$(LINUX_VER)-xen: pristine-linux-src
	$(RM) -rf linux-$(LINUX_VER)-xen
	tar -x -z -f $(LINUX_SRC)
	mv linux-$(LINUX_VER) linux-$(LINUX_VER)-xen
	( cd linux-$(LINUX_VER)-xen-sparse ; ./mkbuildtree ../linux-$(LINUX_VER)-xen )

config_%: linux-$(LINUX_VER)-xen
	$(MAKE) -C linux-$(LINUX_VER)-xen ARCH=xen mrproper
	cp $(LINUX_CONFIG_DIR)/config-$(LINUX_VER)-$(subst config_,,$(@)) .config || $(MAKE) -C linux-$(LINUX_VER)-xen ARCH=xen $(subst config_,,$(@))_config
	$(MAKE) -C linux-$(LINUX_VER)-xen ARCH=xen oldconfig
	$(MAKE) -C linux-$(LINUX_VER)-xen ARCH=xen dep

build_%: 
	$(MAKE) -C linux-$(LINUX_VER)-xen ARCH=xen bzImage
	$(MAKE) -C linux-$(LINUX_VER)-xen ARCH=xen INSTALL_NAME=$(subst linux_,$(LINUX_VER)-,$(@)) prefix=$(INSTALL_DIR) install


world: dist
	$(MAKE) config_xenU 
	$(MAKE) build_xenU
	$(MAKE) config_xen0 
	$(MAKE) build_xen0


clean: delete-symlinks
	$(MAKE) -C xen clean
	$(MAKE) -C tools clean

mrproper: clean
	rm -rf install linux-$(LINUX_VER)-xen linux-$(LINUX_VER).tar.gz


make-symlinks: delete-symlinks
	ln -sf linux-$(LINUX_VER)-xen-sparse linux-xen-sparse

delete-symlinks:
	$(RM) linux-xen-sparse


