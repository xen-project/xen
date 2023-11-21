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
# DomU rootfs
cd initrd
find . | cpio --create --format='newc' | gzip > ../initrd.cpio.gz
cd ..

# initrd.tar.gz is Dom0 rootfs
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
cp ../bzImage ./root
echo "name=\"test\"
memory=512
vcpus=1
kernel=\"/root/bzImage\"
ramdisk=\"/root/initrd.cpio.gz\"
extra=\"console=hvc0 root=/dev/ram0 rdinit=/bin/sh\"
" > root/test.cfg
echo "#!/bin/bash

set -x

export LD_LIBRARY_PATH=/usr/local/lib
bash /etc/init.d/xencommons start

xl list

xl create -c /root/test.cfg

" > etc/local.d/xen.start
chmod +x etc/local.d/xen.start
echo "rc_verbose=yes" >> etc/rc.conf
# rebuild Dom0 rootfs
find . |cpio -H newc -o|gzip > ../xen-rootfs.cpio.gz
cd ../..

cat >> binaries/pxelinux.0 << EOF
#!ipxe

kernel xen console=com1 console_timestamps=boot
module bzImage console=hvc0
module xen-rootfs.cpio.gz
boot
EOF

# Run the test
rm -f smoke.serial
set +e
timeout -k 1 720 \
qemu-system-x86_64 \
    -cpu qemu64,+svm \
    -m 2G -smp 2 \
    -monitor none -serial stdio \
    -nographic \
    -device virtio-net-pci,netdev=n0 \
    -netdev user,id=n0,tftp=binaries,bootfile=/pxelinux.0 |& \
        # Remove carriage returns from the stdout output, as gitlab
        # interface chokes on them
        tee smoke.serial | sed 's/\r//'

set -e
(grep -q "Domain-0" smoke.serial && grep -q "BusyBox" smoke.serial) || exit 1
exit 0
