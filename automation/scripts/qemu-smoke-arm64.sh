#!/bin/bash

set -ex

# Install QEMU
export DEBIAN_FRONTENT=noninteractive
apt-get -qy update
apt-get -qy install --no-install-recommends qemu-system-aarch64 \
                                            u-boot-qemu

# XXX Silly workaround to get the following QEMU command to work
# QEMU looks for "efi-virtio.rom" even if it is unneeded
cp /usr/share/qemu/pvh.bin /usr/share/qemu/efi-virtio.rom
qemu-system-aarch64 \
   -machine virtualization=true \
   -cpu cortex-a57 -machine type=virt \
   -m 512 -display none \
   -machine dumpdtb=binaries/virt-gicv3.dtb

rm -f smoke.serial
set +e
echo "  booti 0x49000000 - 0x44000000" | timeout -k 1 30 qemu-system-aarch64 \
    -machine virtualization=true \
    -cpu cortex-a57 -machine type=virt \
    -m 512 -monitor none -serial stdio \
    -no-reboot \
    -device loader,file=binaries/virt-gicv3.dtb,force-raw=on,addr=0x44000000 \
    -device loader,file=binaries/xen,force-raw=on,addr=0x49000000 \
    -bios /usr/lib/u-boot/qemu_arm64/u-boot.bin |& tee smoke.serial

set -e
grep -q 'LOADING DOMAIN 0' smoke.serial || exit 1
exit 0
