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
	$(MAKE) prefix=`pwd`/../install dist=yes -C xen install
	$(MAKE) prefix=`pwd`/../install dist=yes -C tools install

LINUX_VER        ?= $(shell ( /bin/ls -ld linux-*-xen-sparse ) 2>/dev/null | sed -e 's!^.*linux-\(.\+\)-xen-sparse!\1!' )
LINUX_SRC        ?= ../linux-$(LINUX_VER).tar.gz
LINUX_CONFIG_DIR ?= ../install/config

linux: 
	# build whatever is in the current linux directory
	( cd ../linux-$(LINUX_VER)-xen ; ARCH=xen make bzImage )

world: dist
	mkdir -p ../install/config
	$(RM) -rf ../linux-$(LINUX_VER)-xen
	[ -e $(LINUX_SRC) ] || wget ftp://ftp.kernel.org/pub/linux/kernel/v2.4/linux-$(LINUX_VER).tar.gz -O- > ../linux-$(LINUX_VER).tar.gz
	tar -x -z -C .. -f $(LINUX_SRC)
	mv ../linux-$(LINUX_VER) ../linux-$(LINUX_VER)-xen
	( cd linux-$(LINUX_VER)-xen-sparse ; ./mkbuildtree ../../linux-$(LINUX_VER)-xen )
	cp $(LINUX_CONFIG_DIR)/dom0 ../linux-$(LINUX_VER)-xen/.config || cp linux-$(LINUX_VER)-xen-sparse/arch/xen/defconfigs/dom0 ../linux-$(LINUX_VER)-xen/.config
	( cd ../linux-$(LINUX_VER)-xen; ARCH=xen make oldconfig; ARCH=xen make dep; ARCH=xen make bzImage )
	install -m0644 ../linux-$(LINUX_VER)-xen/arch/xen/boot/bzImage \
		../install/boot/vmlinuz-$(LINUX_VER)-xen0
	install -m0644 ../linux-$(LINUX_VER)-xen/vmlinux ../install/boot/vmlinux-syms-$(LINUX_VER)-xen0
	install -m0644 ../linux-$(LINUX_VER)-xen/.config $(LINUX_CONFIG_DIR)/dom0
	( cd ../linux-$(LINUX_VER)-xen ; ARCH=xen make mrproper )
	cp $(LINUX_CONFIG_DIR)/unprivileged ../linux-$(LINUX_VER)-xen/.config || cp linux-$(LINUX_VER)-xen-sparse/arch/xen/defconfigs/unprivileged ../linux-$(LINUX_VER)-xen/.config 
	( cd ../linux-$(LINUX_VER)-xen; ARCH=xen make oldconfig; ARCH=xen make dep; ARCH=xen make bzImage )
	install -m0644 ../linux-$(LINUX_VER)-xen/arch/xen/boot/bzImage \
		../install/boot/vmlinuz-$(LINUX_VER)-xen
	install -m0644 ../linux-$(LINUX_VER)-xen/vmlinux ../install/boot/vmlinux-syms-$(LINUX_VER)-xen
	install -m0644 ../linux-$(LINUX_VER)-xen/.config $(LINUX_CONFIG_DIR)/unprivileged

clean: delete-symlinks
	$(MAKE) -C xen clean
	$(MAKE) -C tools clean

make-symlinks: delete-symlinks
	ln -sf linux-$(LINUX_VER)-xen-sparse linux-xen-sparse

delete-symlinks:
	$(RM) linux-xen-sparse
 