#!/bin/bash

set -ex

# variant should be either pv or pvh
variant=$1

# Clone and build XTF
git clone https://xenbits.xen.org/git-http/xtf.git
cd xtf && make -j$(nproc) && cd -

case $variant in
    pvh) k=test-hvm64-example    extra="dom0-iommu=none dom0=pvh" ;;
    *)   k=test-pv64-example     extra= ;;
esac

rm -f smoke.serial
set +e
timeout -k 1 30 \
qemu-system-x86_64 -nographic -kernel binaries/xen \
        -initrd xtf/tests/example/$k \
        -append "loglvl=all console=com1 noreboot console_timestamps=boot $extra" \
        -m 512 -monitor none -serial file:smoke.serial
set -e
grep -q 'Test result: SUCCESS' smoke.serial || exit 1
exit 0
