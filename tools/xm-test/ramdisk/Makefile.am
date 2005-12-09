
EXTRA_DIST = skel configs patches

BR_TAR = buildroot-20050823.tar.bz2
BR_URL = http://buildroot.uclibc.org/downloads/snapshots/$(BR_TAR)
#BR_URL = http://buildroot.uclibc.org/downloads/snapshots/buildroot-snapshot.tar.bz2
BR_SRC = buildroot
BR_IMG = $(BR_SRC)/rootfs.i386.ext2

BR_ROOT = build_i386/root

VMX_SCRIPT = bin/create_disk_image

XMTEST_MAJ_VER = $(shell echo @PACKAGE_VERSION@ | perl -pe 's/(\d+)\.(\d+)\.\d+/\1.\2/')
XMTEST_VER_IMG = initrd-$(XMTEST_MAJ_VER).img

if VMX
all: initrd.img disk.img
else
all: initrd.img
endif

$(BR_TAR):
	wget $(BR_URL)

$(BR_SRC): $(BR_TAR)
	tar xjf $(BR_TAR)

$(BR_IMG): $(BR_SRC)
	cp configs/buildroot $(BR_SRC)/.config
	cp configs/busybox $(BR_SRC)/package/busybox/busybox.config
	cp configs/uClibc $(BR_SRC)/toolchain/uClibc/uClibc.config
	(for i in patches/buildroot/*.patch; do \
	  cd $(BR_SRC) && patch -p1 <../$$i; done )
	cd $(BR_SRC) && make oldconfig && make

$(XMTEST_VER_IMG): $(BR_IMG)
	chmod a+x skel/etc/init.d/rcS
	(cd skel; tar cf - .) | (cd $(BR_SRC)/$(BR_ROOT); tar xvf -)
	cd $(BR_SRC) && make
	cp $(BR_IMG) initrd-$(XMTEST_MAJ_VER).img

initrd.img: $(XMTEST_VER_IMG)
	ln -sf $(XMTEST_VER_IMG) initrd.img

disk.img: $(XMTEST_VER_IMG)
	chmod a+x $(VMX_SCRIPT)
	$(VMX_SCRIPT) -r $(XMTEST_VER_IMG) -i disk.img

existing:
	@[ -f $(XMTEST_VER_IMG) ] && ln -sf $(XMTEST_VER_IMG) initrd.img || \
	echo Error, $(XMTEST_VER_IMG) not found

clean-local: am_config_clean-local

am_config_clean-local:
	rm -Rf buildroot
	rm -f *~
	rm -f initrd.img
	rm -f $(BR_TAR)
	rm -Rf patches make.d
	rm -f disk.img
