#!/bin/bash

set -ex

# Run the test
rm -f smoke.serial
set +e

timeout -k 1 2 \
qemu-system-riscv64 \
    -M virt \
    -smp 1 \
    -nographic \
    -m 2g \
    -kernel binaries/xen \
    |& tee smoke.serial | sed 's/\r//'

set -e
(grep -q "All set up" smoke.serial) || exit 1
exit 0
