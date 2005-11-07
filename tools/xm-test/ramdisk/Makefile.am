
EXTRA_DIST = skel configs

BR_TAR = buildroot-20050823.tar.bz2
BR_URL = http://buildroot.uclibc.org/downloads/snapshots/$(BR_TAR)
#BR_URL = http://buildroot.uclibc.org/downloads/snapshots/buildroot-snapshot.tar.bz2
BR_SRC = buildroot
BR_IMG = $(BR_SRC)/rootfs.i386.ext2

BR_ROOT = build_i386/root

all: initrd.img

$(BR_TAR):
	wget $(BR_URL)

$(BR_SRC): $(BR_TAR)
	tar xjf $(BR_TAR)

$(BR_IMG): $(BR_SRC)
	cp configs/buildroot $(BR_SRC)/.config
	cp configs/busybox $(BR_SRC)/package/busybox/busybox.config
	cp configs/uClibc $(BR_SRC)/toolchain/uClibc/uClibc.config
	cd $(BR_SRC) && make oldconfig && make

initrd.img: $(BR_IMG)
	(cd skel; tar cf - .) | (cd $(BR_SRC)/$(BR_ROOT); tar xvf -)
	cd $(BR_SRC) && make
	cp $(BR_IMG) initrd.img

clean-local: am_config_clean-local

am_config_clean-local:
	rm -Rf buildroot
	rm -f *~
	rm -f initrd.img
	rm -f $(BR_TAR)
	rm -Rf patches make.d
