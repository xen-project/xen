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

LINUX_SRC        ?= ../linux-2.4.26.tar.gz
LINUX_CONFIG_DIR ?= ../install/config
world: dist
	$(RM) ../linux-2.4.26-xen
	tar -x -z -C .. -f $(LINUX_SRC)
	mv ../linux-2.4.26 ../linux-2.4.26-xen
	cd ../linux-2.4.26-xen
	cp $(LINUX_CONFIG_DIR)/dom0 .config
	ARCH=xen make oldconfig; ARCH=xen make dep; ARCH=xen make bzImage
	install -m0644 arch/xen/boot/bzImage \
		../install/boot/vmlinuz-2.4.26-xen0
	install -m0644 vmlinux ../install/boot/vmlinux-syms-2.4.26-xen0
	ARCH=xen make mrproper
	cp $(LINUX_CONFIG_DIR)/unprivileged .config
	ARCH=xen make oldconfig; ARCH=xen make dep; ARCH=xen make bzImage
	install -m0644 arch/xen/boot/bzImage \
		../install/boot/vmlinuz-2.4.26-xen
	install -m0644 vmlinux ../install/boot/vmlinux-syms-2.4.26-xen

clean: delete-symlinks
	$(MAKE) -C xen clean
	$(MAKE) -C tools clean

make-symlinks:
	ln -sf linux-2.4.26-xen-sparse linux-xen-sparse

delete-symlinks:
	$(RM) linux-xen-sparse
