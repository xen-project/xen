#
# Grand Unified Makefile for Xen.
#

all: make-symlinks
	$(MAKE) -C xen
	$(MAKE) -C tools

install: all
	$(MAKE) -C xen install
	$(MAKE) -C tools install

dist: all
	$(MAKE) prefix=`pwd`/install dist=yes -C xen install
	$(MAKE) prefix=`pwd`/install dist=yes -C tools install

LINUX_VER        ?= $(shell ( /bin/ls -ld linux-*-xen-sparse ) 2>/dev/null | sed -e 's!^.*linux-\(.\+\)-xen-sparse!\1!' )
LINUX_SRC        ?= linux-$(LINUX_VER).tar.gz
LINUX_CONFIG_DIR ?= install/boot

linux: 
	# build whatever is in the current linux directory
	( cd ../linux-$(LINUX_VER)-xen ; ARCH=xen make bzImage )

linux-src:
	[ -e $(LINUX_SRC) ] || wget ftp://ftp.kernel.org/pub/linux/kernel/v2.4/linux-$(LINUX_VER).tar.gz -O- > linux-$(LINUX_VER).tar.gz

mklinux-xen-tree: linux-src
	$(RM) -rf linux-$(LINUX_VER)-xen
	tar -x -z -f $(LINUX_SRC)
	mv linux-$(LINUX_VER) linux-$(LINUX_VER)-xen
	( cd linux-$(LINUX_VER)-xen-sparse ; ./mkbuildtree ../linux-$(LINUX_VER)-xen )

world: dist mklinux-xen-tree
	cp ../$(LINUX_CONFIG_DIR)/config-$(LINUX_VER)-xenU .config || make -C linux-$(LINUX_VER)-xen ARCH=xen xenU_config
	make -C linux-$(LINUX_VER)-xen ARCH=xen oldconfig
	make -C linux-$(LINUX_VER)-xen ARCH=xen dep
	make -C linux-$(LINUX_VER)-xen ARCH=xen bzImage
	INSTALLSUFFIX=U make -C linux-$(LINUX_VER)-xen ARCH=xen dist
	make -C linux-$(LINUX_VER)-xen ARCH=xen mrproper
	cp ../$(LINUX_CONFIG_DIR)/config-$(LINUX_VER)-xen0 .config || ARCH=xen make ARCH=xen xen0_config
	make -C linux-$(LINUX_VER)-xen ARCH=xen oldconfig
	make -C linux-$(LINUX_VER)-xen ARCH=xen dep
	make -C linux-$(LINUX_VER)-xen ARCH=xen bzImage
	INSTALLSUFFIX=0 make -C linux-$(LINUX_VER)-xen ARCH=xen dist

clean: delete-symlinks
	$(MAKE) -C xen clean
	$(MAKE) -C tools clean

make-symlinks: delete-symlinks
	ln -sf linux-$(LINUX_VER)-xen-sparse linux-xen-sparse

delete-symlinks:
	$(RM) linux-xen-sparse
 
