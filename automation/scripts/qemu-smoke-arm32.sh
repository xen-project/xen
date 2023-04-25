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

kernel=`stat -L --printf="%s" vmlinuz`
initrd=`stat -L --printf="%s" initrd.gz`

# For Xen, we need a couple of more node. Dump the DT from QEMU and add them
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

dtc -I dtb -O dts virt.dtb > virt.dts

cat >> virt.dts << EOF
/ {
	chosen {
		#address-cells = <0x2>;
		#size-cells = <0x2>;
		stdout-path = "/pl011@9000000";
        xen,xen-bootargs = "console=dtuart dtuart=/pl011@9000000 dom0_mem=512M bootscrub=0";
		xen,dom0-bootargs = "console=tty0 console=hvc0 earlyprintk clk_ignore_unused root=/dev/ram0 rdinit=/bin/sh";
		dom0 {
			compatible = "xen,linux-zimage", "xen,multiboot-module";
			reg = <0x0 0x1000000 0x0 $kernel>;
		};
        dom0-ramdisk {
			compatible = "xen,linux-initrd", "xen,multiboot-module";
			reg = <0x0 0x3200000 0x0 $initrd>;
		};
	};
};
EOF
dtc -I dts -O dtb virt.dts > virt.dtb

rm -f smoke.serial
set +e
timeout -k 1 240 \
./qemu-system-arm \
   -machine virt \
   -machine virtualization=true \
   -smp 4 \
   -m 1024 \
   -serial stdio \
   -monitor none \
   -display none \
   -dtb virt.dtb \
   -no-reboot \
   -kernel ./xen \
   -device loader,file=./vmlinuz,addr=0x1000000 \
   -device loader,file=./initrd.gz,addr=0x3200000 |& tee smoke.serial

set -e
(grep -q "^/ #" smoke.serial) || exit 1
exit 0
