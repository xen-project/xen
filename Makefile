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
LINUX_CONFIG_DIR ?= $(INSTALL_DIR)/boot
LINUX_SRC_PATH   ?= .:..
LINUX_SRC_X ?= $(firstword $(foreach dir,$(subst :, ,$(LINUX_SRC_PATH)),$(wildcard $(dir)/linux-$(LINUX_VER).tar.gz)))

pristine-linux-src: 
ifneq ($(LINUX_SRC),)
	@[ -r "$(LINUX_SRC)" ] || (echo "Can not find linux src at $(LINUX_SRC)" && false)
LINUX_SRC_X = $(LINUX_SRC)
else 
ifeq ($(LINUX_SRC_X),)
	@echo "Can not find linux-$(LINUX_VER).tar.gz in path $(LINUX_SRC_PATH)"
	@wget ftp://ftp.kernel.org/pub/linux/kernel/v2.4/linux-$(LINUX_VER).tar.gz -O./linux-$(LINUX_VER).tar.gz
LINUX_SRC_X = ./linux-$(LINUX_VER).tar.gz 
endif
endif

linux-$(LINUX_VER)-xen: pristine-linux-src
	$(RM) -rf linux-$(LINUX_VER)-xen
	tar -x -z -f $(LINUX_SRC_X)
	mv linux-$(LINUX_VER) linux-$(LINUX_VER)-xen
	( cd linux-$(LINUX_VER)-xen-sparse ; ./mkbuildtree ../linux-$(LINUX_VER)-xen )

linux_%_config: 
	$(MAKE) -C linux-$(LINUX_VER)-xen ARCH=xen mrproper
	cp $(LINUX_CONFIG_DIR)/config-$(LINUX_VER)-$(subst _config,,$(subst linux_,,$(@))) .config || $(MAKE) -C linux-$(LINUX_VER)-xen ARCH=xen $(subst linux_,,$(@))
	$(MAKE) -C linux-$(LINUX_VER)-xen ARCH=xen oldconfig
	$(MAKE) -C linux-$(LINUX_VER)-xen ARCH=xen dep

linux:	
	$(MAKE) -C linux-$(LINUX_VER)-xen ARCH=xen INSTALL_PATH=$(INSTALL_DIR) install	

linux_%: 
	$(MAKE) -C linux-$(LINUX_VER)-xen ARCH=xen INSTALL_NAME=$(subst linux_,$(LINUX_VER)-,$(@)) INSTALL_PATH=$(INSTALL_DIR) install


world: dist
	$(MAKE) linux-$(LINUX_VER)-xen
	$(MAKE) linux_xenU_config
	$(MAKE) linux_xenU
	$(MAKE) linuc_xen0_config
	$(MAKE) linux_xen0


clean: delete-symlinks
	$(MAKE) -C xen clean
	$(MAKE) -C tools clean

mrproper: clean
	rm -rf install linux-$(LINUX_VER)-xen linux-$(LINUX_VER).tar.gz


make-symlinks: delete-symlinks
	ln -sf linux-$(LINUX_VER)-xen-sparse linux-xen-sparse

delete-symlinks:
	$(RM) linux-xen-sparse


