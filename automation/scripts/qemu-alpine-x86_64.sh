#!/bin/bash

set -ex -o pipefail

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
# DomU rootfs
cd initrd
find . | cpio -H newc -o | gzip > ../domU-rootfs.cpio.gz
cd ..

# Dom0 rootfs
cp rootfs.cpio.gz dom0-rootfs.cpio.gz
cat xen-tools.cpio.gz >> dom0-rootfs.cpio.gz

# test-local configuration
mkdir -p rootfs
cd rootfs
mkdir -p root etc/local.d
mv ../domU-rootfs.cpio.gz ./root
cp ../bzImage ./root
echo "name=\"domU\"
memory=512
vcpus=1
kernel=\"/root/bzImage\"
ramdisk=\"/root/domU-rootfs.cpio.gz\"
extra=\"console=hvc0 root=/dev/ram0 rdinit=/bin/sh\"
" > root/domU.cfg
echo "#!/bin/bash

set -x

bash /etc/init.d/xencommons start

xl list

xl -vvv create -c /root/domU.cfg

" > etc/local.d/xen.start
chmod +x etc/local.d/xen.start
find . | cpio -H newc -o | gzip >> ../dom0-rootfs.cpio.gz
cd ../..

cat >> binaries/pxelinux.0 << EOF
#!ipxe

kernel xen console=com1 console_timestamps=boot
module bzImage console=hvc0
module dom0-rootfs.cpio.gz
boot
EOF

# Run the test
rm -f smoke.serial
export TEST_CMD="qemu-system-x86_64 \
    -cpu qemu64,+svm \
    -m 2G -smp 2 \
    -monitor none -serial stdio \
    -nographic \
    -device virtio-net-pci,netdev=n0 \
    -netdev user,id=n0,tftp=binaries,bootfile=/pxelinux.0"

export TEST_LOG="smoke.serial"
export BOOT_MSG="Latest ChangeSet: "
export LOG_MSG="Domain-0"
export PASSED="BusyBox"

./automation/scripts/console.exp | sed 's/\r\+$//'
