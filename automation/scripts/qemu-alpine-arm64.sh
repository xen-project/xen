#!/bin/bash

set -ex

apt-get -qy update
apt-get -qy install --no-install-recommends qemu-system-aarch64 \
                                            u-boot-qemu \
                                            u-boot-tools \
                                            device-tree-compiler \
                                            cpio \
                                            curl

mkdir -p binaries/rootfs
cd binaries/rootfs
tar xvzf ../initrd.tar.gz
mkdir proc
mkdir run
mkdir srv
mkdir sys
rm var/run
cp -ar ../dist/install/* .
echo "#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/lib
bash /etc/init.d/xencommons start

xl list

" > etc/local.d/xen.start
chmod +x etc/local.d/xen.start
echo "rc_verbose=yes" >> etc/rc.conf
find . |cpio -H newc -o|gzip > ../xen-rootfs.cpio.gz
cd ../..

# XXX Silly workaround to get the following QEMU command to work
# QEMU looks for "efi-virtio.rom" even if it is unneeded
cp /usr/share/qemu/pvh.bin /usr/share/qemu/efi-virtio.rom
qemu-system-aarch64 \
   -machine virtualization=true \
   -cpu cortex-a57 -machine type=virt \
   -m 1024 -display none \
   -machine dumpdtb=binaries/virt-gicv3.dtb
# XXX disable pl061 to avoid Linux crash
dtc -I dtb -O dts binaries/virt-gicv3.dtb > binaries/virt-gicv3.dts
sed 's/compatible = "arm,pl061.*/status = "disabled";/g' binaries/virt-gicv3.dts > binaries/virt-gicv3-edited.dts
dtc -I dts -O dtb binaries/virt-gicv3-edited.dts > binaries/virt-gicv3.dtb

# ImageBuilder
echo 'MEMORY_START="0x40000000"
MEMORY_END="0x80000000"

DEVICE_TREE="virt-gicv3.dtb"
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
timeout -k 1 480 \
qemu-system-aarch64 \
    -machine virtualization=true \
    -cpu cortex-a57 -machine type=virt \
    -m 2048 -monitor none -serial stdio \
    -smp 2 \
    -no-reboot \
    -device virtio-net-pci,netdev=n0 \
    -netdev user,id=n0,tftp=binaries \
    -bios /usr/lib/u-boot/qemu_arm64/u-boot.bin |& tee smoke.serial

set -e
grep -q "Domain-0" smoke.serial || exit 1
exit 0
