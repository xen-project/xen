#!/bin/bash

set -ex

# machine type from first arg passed directly to qemu -M
machine=$1

# Run the test
rm -f smoke.serial
set +e

touch smoke.serial

timeout -k 1 20 \
qemu-system-ppc64 \
    -M $machine \
    -m 2g \
    -smp 1 \
    -vga none \
    -monitor none \
    -nographic \
    -serial file:smoke.serial \
    -kernel binaries/xen

set -e
(grep -q "Hello, ppc64le!" smoke.serial) || exit 1
exit 0
