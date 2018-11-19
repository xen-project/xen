#!/bin/bash

set -ex

# Install QEMU
export DEBIAN_FRONTENT=noninteractive
apt-get -qy update
apt-get -qy install qemu-system-x86

# Clone and build XTF
git clone https://xenbits.xen.org/git-http/xtf.git
cd xtf && make -j$(nproc) && cd -

rm -f smoke.serial
set +e
timeout -k 1 10 \
qemu-system-x86_64 -nographic -kernel binaries/xen \
        -initrd xtf/tests/example/test-pv32pae-example \
        -append 'loglvl=all com1=115200,,8n1 console=com1 noreboot' \
        -m 512 -monitor none -serial file:smoke.serial
set -e
grep -q 'Test result: SUCCESS' smoke.serial || exit 1
exit 0
