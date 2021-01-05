#!/bin/bash

set -ex

# Install QEMU
export DEBIAN_FRONTENT=noninteractive
apt-get -qy update
apt-get -qy install --no-install-recommends u-boot-qemu \
                                            u-boot-tools \
                                            device-tree-compiler \
                                            busybox-static \
                                            cpio \
                                            curl

# XXX QEMU looks for "efi-virtio.rom" even if it is unneeded
curl -fsSLO https://github.com/qemu/qemu/raw/v5.2.0/pc-bios/efi-virtio.rom
./binaries/qemu-system-aarch64 \
   -machine virtualization=true \
   -cpu cortex-a57 -machine type=virt \
   -m 1024 -display none \
   -machine dumpdtb=binaries/virt-gicv3.dtb
# XXX disable pl061 to avoid Linux crash
dtc -I dtb -O dts binaries/virt-gicv3.dtb > binaries/virt-gicv3.dts
sed 's/compatible = "arm,pl061.*/status = "disabled";/g' binaries/virt-gicv3.dts > binaries/virt-gicv3-edited.dts
dtc -I dts -O dtb binaries/virt-gicv3-edited.dts > binaries/virt-gicv3.dtb


# Busybox Dom0
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
find . | cpio --create --format='newc' | gzip > ../binaries/initrd
cd ..


# ImageBuilder
echo 'MEMORY_START="0x40000000"
MEMORY_END="0x80000000"

DEVICE_TREE="virt-gicv3.dtb"
XEN="xen"
DOM0_KERNEL="Image"
DOM0_RAMDISK="initrd"
XEN_CMD="console=dtuart dom0_mem=512M"

NUM_DOMUS=1
DOMU_KERNEL[0]="Image"
DOMU_RAMDISK[0]="initrd"
DOMU_MEM[0]="256"

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
timeout -k 1 240 \
./binaries/qemu-system-aarch64 \
    -machine virtualization=true \
    -cpu cortex-a57 -machine type=virt \
    -m 1024 -monitor none -serial stdio \
    -smp 2 \
    -no-reboot \
    -device virtio-net-pci,netdev=n0 \
    -netdev user,id=n0,tftp=binaries \
    -bios /usr/lib/u-boot/qemu_arm64/u-boot.bin |& tee smoke.serial

set -e
(grep -q "^BusyBox" smoke.serial && grep -q "DOM1: BusyBox" smoke.serial) || exit 1
exit 0
