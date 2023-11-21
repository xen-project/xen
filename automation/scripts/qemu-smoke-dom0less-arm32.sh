#!/bin/bash

set -ex

test_variant=$1

# Prompt to grep for to check if dom0 booted successfully
dom0_prompt="^/ #"

serial_log="$(pwd)/smoke.serial"

cd binaries
# Use the kernel from Debian
curl --fail --silent --show-error --location --output vmlinuz https://deb.debian.org/debian/dists/bullseye/main/installer-armhf/current/images/netboot/vmlinuz
# Use a tiny initrd based on busybox from Alpine Linux
curl --fail --silent --show-error --location --output initrd.tar.gz https://dl-cdn.alpinelinux.org/alpine/v3.15/releases/armhf/alpine-minirootfs-3.15.1-armhf.tar.gz

if [ -z "${test_variant}" ]; then
    passed="generic test passed"
    domU_check="
echo \"${passed}\"
"
fi

if [[ "${test_variant}" == "static-mem" ]]; then
    # Memory range that is statically allocated to domU1
    domu_base="0x50000000"
    domu_size="0x20000000"
    passed="${test_variant} test passed"
    domU_check="
mem_range=$(printf \"%08x-%08x\" ${domu_base} $(( ${domu_base} + ${domu_size} - 1 )))
if grep -q -x \"\${mem_range} : System RAM\" /proc/iomem; then
    echo \"${passed}\"
fi
"
fi

if [[ "${test_variant}" == "gzip" ]]; then
    # Compress kernel image with gzip (keep unmodified one for dom0)
    gzip -k vmlinuz
    passed="${test_variant} test passed"
    domU_check="
echo \"${passed}\"
"
fi

if [[ "${test_variant}" == "without-dom0" ]]; then
    # Clear dom0 prompt
    dom0_prompt=""
    passed="${test_variant} test passed"
    domU_check="
echo \"${passed}\"
"
fi

# dom0/domU rootfs
# We are using the same rootfs for dom0 and domU. The only difference is
# that for the former, we set explictly rdinit to /bin/sh, whereas for the
# latter we rely on using custom /init script with test case inside.
mkdir rootfs
cd rootfs
tar xvzf ../initrd.tar.gz
echo "#!/bin/sh

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
${domU_check}
/bin/sh" > init
chmod +x init
find . | cpio -H newc -o | gzip > ../initrd.gz
cd ..

# XXX QEMU looks for "efi-virtio.rom" even if it is unneeded
curl -fsSLO https://github.com/qemu/qemu/raw/v5.2.0/pc-bios/efi-virtio.rom
./qemu-system-arm \
    -machine virt \
    -machine virtualization=true \
    -smp 4 \
    -m 2048 \
    -serial stdio \
    -monitor none \
    -display none \
    -machine dumpdtb=virt.dtb

# ImageBuilder
echo 'MEMORY_START="0x40000000"
MEMORY_END="0xC0000000"

DEVICE_TREE="virt.dtb"
XEN="xen"
XEN_CMD="console=dtuart dom0_mem=512M bootscrub=0"

DOM0_KERNEL="vmlinuz"
DOM0_RAMDISK="initrd.gz"
DOM0_CMD="console=hvc0 earlyprintk clk_ignore_unused root=/dev/ram0 rdinit=/bin/sh"

DOMU_KERNEL[0]="vmlinuz"
DOMU_RAMDISK[0]="initrd.gz"
DOMU_MEM[0]="512"
NUM_DOMUS=1

LOAD_CMD="tftpb"
BOOT_CMD="bootm"
UBOOT_SOURCE="boot.source"
UBOOT_SCRIPT="boot.scr"' > config

if [[ "${test_variant}" == "static-mem" ]]; then
    echo -e "\nDOMU_STATIC_MEM[0]=\"${domu_base} ${domu_size}\"" >> config
fi

if [[ "${test_variant}" == "gzip" ]]; then
    sed -i 's/DOMU_KERNEL\[0\]=.*/DOMU_KERNEL\[0\]="vmlinuz.gz"/' config
fi

if [[ "${test_variant}" == "without-dom0" ]]; then
    sed -i '/^DOM0/d' config
fi

rm -rf imagebuilder
git clone https://gitlab.com/ViryaOS/imagebuilder
bash imagebuilder/scripts/uboot-script-gen -t tftp -d . -c config

# Run the test
rm -f ${serial_log}
set +e
echo "  virtio scan; dhcp; tftpb 0x40000000 boot.scr; source 0x40000000"| \
timeout -k 1 240 \
./qemu-system-arm \
    -machine virt \
    -machine virtualization=true \
    -smp 4 \
    -m 2048 \
    -serial stdio \
    -monitor none \
    -display none \
    -no-reboot \
    -device virtio-net-pci,netdev=n0 \
    -netdev user,id=n0,tftp=./ \
    -bios /usr/lib/u-boot/qemu_arm/u-boot.bin |& \
        tee ${serial_log} | sed 's/\r//'

set -e
(grep -q "${dom0_prompt}" ${serial_log} && grep -q "${passed}" ${serial_log}) || exit 1
exit 0
