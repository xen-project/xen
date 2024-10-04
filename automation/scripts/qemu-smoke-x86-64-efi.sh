#!/bin/bash

set -ex -o pipefail

# variant should be either pv or pvh
variant=$1

# Clone and build XTF
git clone https://xenbits.xen.org/git-http/xtf.git
cd xtf && make -j$(nproc) && cd -

case $variant in
    pvh) k=test-hvm64-example    extra="dom0-iommu=none dom0=pvh" ;;
    *)   k=test-pv64-example     extra= ;;
esac

mkdir -p boot-esp/EFI/BOOT
cp binaries/xen.efi boot-esp/EFI/BOOT/BOOTX64.EFI
cp xtf/tests/example/$k boot-esp/EFI/BOOT/kernel

cat > boot-esp/EFI/BOOT/BOOTX64.cfg <<EOF
[global]
default=test

[test]
options=loglvl=all console=com1 noreboot console_timestamps=boot $extra
kernel=kernel
EOF

cp /usr/share/OVMF/OVMF_CODE.fd OVMF_CODE.fd
cp /usr/share/OVMF/OVMF_VARS.fd OVMF_VARS.fd

rm -f smoke.serial
export TEST_CMD="qemu-system-x86_64 -nographic -M q35,kernel-irqchip=split \
        -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd \
        -drive if=pflash,format=raw,file=OVMF_VARS.fd \
        -drive file=fat:rw:boot-esp,media=disk,index=0,format=raw \
        -m 512 -monitor none -serial stdio"

export TEST_LOG="smoke.serial"
export PASSED="Test result: SUCCESS"

./automation/scripts/console.exp | sed 's/\r\+$//'
