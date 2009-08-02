#
# make existing:
#
#   Download a pre-built ramdisk.
#     INITRD = <Directory to download ramdisk from>
#
# make initrd.img:
#
#   Make a ramdisk from scratch.
#     BR_URL = <The URL of the Buildroot source code>
#     BR_SNAPSHOT = 1  Set BR_URL to the upstream Buildroot daily snapshot.
#     BR_ARCH = <The build architecture for the initrd>
#

INITRD ?= http://xm-test.xensource.com/ramdisks

BR_ARCH ?= $(shell uname -m | sed -e 's/i.86/i386/' -e 's/x86_64/i386/')

@MK@ifdef BR_SNAPSHOT
@MK@  BR_URL = http://buildroot.uclibc.org/downloads/snapshots/buildroot-snapshot.tar.bz2
@MK@else
@MK@  BR_URL = http://xm-test.xensource.com/ramdisks/buildroot-20061023.tar.bz2
@MK@endif
BR_TAR = $(notdir $(BR_URL))

BR_SRC = buildroot
BR_IMG = $(BR_SRC)/rootfs.$(BR_ARCH).ext2

BR_ROOT = build_$(BR_ARCH)/root

EXTRA_DIST = skel configs patches

HVM_SCRIPT = bin/create_disk_image

XMTEST_MAJ_VER = $(shell echo @PACKAGE_VERSION@ | perl -pe 's/(\d+)\.(\d+)\.\d+/\1.\2/')
XMTEST_VER_IMG = initrd-$(XMTEST_MAJ_VER)-$(BR_ARCH).img
XMTEST_DL_IMG = $(shell echo $(XMTEST_VER_IMG) | sed -e 's/x86_64/i386/g')

EXTRA_ROOT_DIRS = sys modules

BLKDRV = /lib/modules/$(shell uname -r)/kernel/drivers/xen/blkfront/xenblk.ko
NETDRV = /lib/modules/$(shell uname -r)/kernel/drivers/xen/netfront/xennet.ko
PKTDRV = /lib/modules/$(shell uname -r)/kernel/net/packet/af_packet.ko


if HVM
all: initrd.img disk.img
else
all: initrd.img
endif

$(BR_TAR):
	wget $(BR_URL)

$(BR_SRC): $(BR_TAR)
	tar xjf $(BR_TAR)

$(BR_IMG): $(BR_SRC)
	cp configs/buildroot-$(BR_ARCH) $(BR_SRC)/.config
	cp configs/busybox $(BR_SRC)/package/busybox/busybox.config
	cp configs/uClibc $(BR_SRC)/toolchain/uClibc/uClibc.config
	set -e; for i in patches/buildroot/*.patch; do \
	  cd $(BR_SRC) && patch -p1 <../$$i && cd ..; done
	cd $(BR_SRC) && make oldconfig && make

$(XMTEST_VER_IMG): $(BR_IMG)
	chmod a+x skel/etc/init.d/rcS
	cd skel && mkdir -p $(EXTRA_ROOT_DIRS)
	-[ -e "$(BLKDRV)" ] && cp $(BLKDRV) skel/modules
	-[ -e "$(NETDRV)" ] && cp $(NETDRV) skel/modules
	-[ -e "$(PKTDRV)" ] && cp $(PKTDRV) skel/modules
	(cd skel && tar cf - .) \
		| (cd $(BR_SRC)/$(BR_ROOT) && tar xvf -)
	cd $(BR_SRC) && make
	cp $(BR_IMG) $(XMTEST_VER_IMG)

initrd.img: $(XMTEST_VER_IMG)
	ln -sf $(XMTEST_VER_IMG) initrd.img

disk.img: existing
	chmod a+x $(HVM_SCRIPT)
	@if test ! "$(HVMKERNEL)" = "no" -a ! "$(DRVDIR)" = "no"; then \
		$(HVM_SCRIPT) -r $(XMTEST_VER_IMG) -k $(HVMKERNEL) \
			-d $(DRVDIR) -n $(NETDRV); \
	elif test "$(HVMKERNEL)" = "no" -a ! "$(DRVDIR)" = "no"; then \
		$(HVM_SCRIPT) -r $(XMTEST_VER_IMG) -d $(DRVDIR) -n $(NETDRV); \
	elif test ! "$(HVMKERNEL)" = "no" -a "$(DRVDIR)" = "no"; then \
		$(HVM_SCRIPT) -r $(XMTEST_VER_IMG) -k $(HVMKERNEL) \
			-n $(NETDRV); \
	else \
		$(HVM_SCRIPT) -r $(XMTEST_VER_IMG) -n $(NETDRV); \
	fi

existing:
	@if [ -n "$(INITRD)" ] && [ ! -f $(XMTEST_VER_IMG) ] ; then \
                if [ ! -f $(XMTEST_DL_IMG) ] ; then \
		        wget $(INITRD)/$(XMTEST_DL_IMG); \
                fi; \
                if [ "$(XMTEST_DL_IMG)" != "$(XMTEST_VER_IMG)" ] ; then \
                        ln -s $(XMTEST_DL_IMG) $(XMTEST_VER_IMG); \
                fi \
	fi
	@if [ -f $(XMTEST_VER_IMG) ] ; then \
		ln -sf $(XMTEST_VER_IMG) initrd.img; \
	else \
		echo Error, $(XMTEST_VER_IMG) not found;  \
		false; \
	fi
# The newer linux kernels have ext2 disabled by default - but the
# initrd is ext2.
# The whole xm-test environment assumes, that the guest system uses
# the same kernel as the dom0.  Therefore the current (dom0's) kernel
# is checked if ext2 is supported.  If not (and ext3 is supported) the
# initrd will be converted to ext3.
	@cat /proc/filesystems | grep -q ext2 && \
	  cat /proc/filesystems | grep -q ext3 || \
	  /sbin/tune2fs -j $(XMTEST_DL_IMG) >/dev/null || true

clean-local: am_config_clean-local

am_config_clean-local:
	rm -Rf buildroot
	rm -f *~
	rm -f initrd.img
	rm -f $(BR_TAR)
	rm -f disk.img
