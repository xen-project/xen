#!/bin/bash

set -ex

# Name of the XTF test
xtf_test=$1

# Message returned by XTF in case of success
passed="Test result: SUCCESS"

# XXX QEMU looks for "efi-virtio.rom" even if it is unneeded
curl -fsSLO https://github.com/qemu/qemu/raw/v5.2.0/pc-bios/efi-virtio.rom
./binaries/qemu-system-aarch64 \
   -machine virtualization=true \
   -cpu cortex-a57 -machine type=virt \
   -m 2048 -smp 2 -display none \
   -machine dumpdtb=binaries/virt-gicv2.dtb

# XTF
# Build a single XTF test passed as a first parameter to the script.
# Build XTF with GICv2 support to match Qemu configuration and with SBSA UART
# support, so that the test will use an emulated UART for printing messages.
# This will allow us to run the test on both debug and non-debug Xen builds.
rm -rf xtf
git clone https://gitlab.com/xen-project/fusa/xtf.git -b xtf-arm
make -C xtf TESTS=tests/${xtf_test} CONFIG_SBSA_UART=y CONFIG_GICV2=y -j$(nproc)
cp xtf/tests/${xtf_test}/test-mmu64le-${xtf_test} binaries/xtf-test

# ImageBuilder
echo 'MEMORY_START="0x40000000"
MEMORY_END="0xC0000000"

XEN="xen"
DEVICE_TREE="virt-gicv2.dtb"

XEN_CMD="console=dtuart console_timestamps=boot"

DOMU_KERNEL[0]="xtf-test"
DOMU_MEM[0]="128"

NUM_DOMUS=1

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
timeout -k 1 120 \
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
(grep -q "${passed}" smoke.serial) || exit 1
exit 0
