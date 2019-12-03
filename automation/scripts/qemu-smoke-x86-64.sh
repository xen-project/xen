#!/bin/bash

set -ex

# variant should be either pv or pvh
variant=$1

# Install QEMU
export DEBIAN_FRONTENT=noninteractive
apt-get -qy update
apt-get -qy install qemu-system-x86

# Clone and build XTF
git clone https://xenbits.xen.org/git-http/xtf.git
cd xtf && make -j$(nproc) && cd -

case $variant in
    pvh) k=test-hvm32pae-example extra="dom0-iommu=none dom0=pvh" ;;
    *)   k=test-pv32pae-example  extra= ;;
esac

rm -f smoke.serial
set +e
timeout -k 1 10 \
qemu-system-x86_64 -nographic -kernel binaries/xen \
        -initrd xtf/tests/example/$k \
        -append "loglvl=all com1=115200,,8n1 console=com1 noreboot \
                 console_timestamps=boot $extra" \
        -m 512 -monitor none -serial file:smoke.serial
set -e
grep -q 'Test result: SUCCESS' smoke.serial || exit 1
exit 0
