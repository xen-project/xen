#!/bin/bash

set -ex

# DomU Busybox
cd binaries
mkdir -p initrd
mkdir -p initrd/bin
mkdir -p initrd/sbin
mkdir -p initrd/etc
mkdir -p initrd/dev
mkdir -p initrd/proc
mkdir -p initrd/sys
mkdir -p initrd/lib
mkdir -p initrd/var
mkdir -p initrd/mnt
cp /bin/busybox initrd/bin/busybox
initrd/bin/busybox --install initrd/bin
echo "#!/bin/sh

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
/bin/sh" > initrd/init
chmod +x initrd/init
cd initrd
find . | cpio --create --format='newc' | gzip > ../initrd.cpio.gz
cd ..

mkdir -p rootfs
cd rootfs
tar xvzf ../initrd.tar.gz
mkdir proc
mkdir run
mkdir srv
mkdir sys
rm var/run
cp -ar ../dist/install/* .
mv ../initrd.cpio.gz ./root
cp ../Image ./root
echo "name=\"test\"
memory=512
vcpus=1
kernel=\"/root/Image\"
ramdisk=\"/root/initrd.cpio.gz\"
extra=\"console=hvc0 root=/dev/ram0 rdinit=/bin/sh\"
" > root/test.cfg
echo "#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/lib
bash /etc/init.d/xencommons start

xl list

xl create -c /root/test.cfg

" > etc/local.d/xen.start
chmod +x etc/local.d/xen.start
echo "rc_verbose=yes" >> etc/rc.conf
find . |cpio -H newc -o|gzip > ../xen-rootfs.cpio.gz
cd ../..

# XXX QEMU looks for "efi-virtio.rom" even if it is unneeded
curl -fsSLO https://github.com/qemu/qemu/raw/v5.2.0/pc-bios/efi-virtio.rom
./binaries/qemu-system-aarch64 \
   -machine virtualization=true \
   -cpu cortex-a57 -machine type=virt \
   -m 2048 -smp 2 -display none \
   -machine dumpdtb=binaries/virt-gicv2.dtb

# XXX disable pl061 to avoid Linux crash
fdtput binaries/virt-gicv2.dtb -p -t s /pl061@9030000 status disabled

# ImageBuilder
echo 'MEMORY_START="0x40000000"
MEMORY_END="0xC0000000"

DEVICE_TREE="virt-gicv2.dtb"
XEN="xen"
DOM0_KERNEL="Image"
DOM0_RAMDISK="xen-rootfs.cpio.gz"
XEN_CMD="console=dtuart dom0_mem=1024M"

NUM_DOMUS=0

LOAD_CMD="tftpb"
UBOOT_SOURCE="boot.source"
UBOOT_SCRIPT="boot.scr"' > binaries/config
rm -rf imagebuilder
git clone https://gitlab.com/ViryaOS/imagebuilder
bash imagebuilder/scripts/uboot-script-gen -t tftp -d binaries/ -c binaries/config


# Run the test
rm -f smoke.serial
set +e
echo "  virtio scan; dhcp; tftpb 0x40000000 boot.scr; source 0x40000000"| \
timeout -k 1 720 \
./binaries/qemu-system-aarch64 \
    -machine virtualization=true \
    -cpu cortex-a57 -machine type=virt \
    -m 2048 -monitor none -serial stdio \
    -smp 2 \
    -no-reboot \
    -device virtio-net-pci,netdev=n0 \
    -netdev user,id=n0,tftp=binaries \
    -bios /usr/lib/u-boot/qemu_arm64/u-boot.bin |& \
        tee smoke.serial | sed 's/\r//'

set -e
(grep -q "Domain-0" smoke.serial && grep -q "BusyBox" smoke.serial) || exit 1
exit 0
