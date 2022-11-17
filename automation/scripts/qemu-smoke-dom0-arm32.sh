#!/bin/bash

set -ex

cd binaries
# Use the kernel from Debian
curl --fail --silent --show-error --location --output vmlinuz http://http.us.debian.org/debian/dists/bullseye/main/installer-armhf/current/images/netboot/vmlinuz
# Use a tiny initrd based on busybox from Alpine Linux
curl --fail --silent --show-error --location --output initrd.tar.gz https://dl-cdn.alpinelinux.org/alpine/v3.15/releases/armhf/alpine-minirootfs-3.15.1-armhf.tar.gz

mkdir rootfs
cd rootfs
tar xvzf ../initrd.tar.gz
find . | cpio -H newc -o | gzip > ../initrd.gz
cd ..

# XXX QEMU looks for "efi-virtio.rom" even if it is unneeded
curl -fsSLO https://github.com/qemu/qemu/raw/v5.2.0/pc-bios/efi-virtio.rom
./qemu-system-arm \
   -machine virt \
   -machine virtualization=true \
   -smp 4 \
   -m 1024 \
   -serial stdio \
   -monitor none \
   -display none \
   -machine dumpdtb=virt.dtb

# ImageBuilder
echo 'MEMORY_START="0x40000000"
MEMORY_END="0x80000000"

DEVICE_TREE="virt.dtb"
XEN="xen"
DOM0_KERNEL="vmlinuz"
DOM0_RAMDISK="initrd.gz"
DOM0_CMD="console=hvc0 earlyprintk clk_ignore_unused root=/dev/ram0 rdinit=/bin/sh"
XEN_CMD="console=dtuart dom0_mem=512M bootscrub=0"

NUM_DOMUS=0

LOAD_CMD="tftpb"
BOOT_CMD="bootm"
UBOOT_SOURCE="boot.source"
UBOOT_SCRIPT="boot.scr"' > config

rm -rf imagebuilder
git clone https://gitlab.com/ViryaOS/imagebuilder
bash imagebuilder/scripts/uboot-script-gen -t tftp -d . -c config

rm -f smoke.serial
set +e
echo "  virtio scan; dhcp; tftpb 0x40000000 boot.scr; source 0x40000000"| \
timeout -k 1 240 \
./qemu-system-arm \
   -machine virt \
   -machine virtualization=true \
   -smp 4 \
   -m 1024 \
   -serial stdio \
   -monitor none \
   -display none \
   -no-reboot \
   -device virtio-net-pci,netdev=n0 \
   -netdev user,id=n0,tftp=./ \
   -bios /usr/lib/u-boot/qemu_arm/u-boot.bin |& tee smoke.serial

set -e
(grep -q "^/ #" smoke.serial) || exit 1
exit 0
