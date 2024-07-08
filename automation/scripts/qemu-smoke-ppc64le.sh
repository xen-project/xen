#!/bin/bash

set -ex

serial_log="$(pwd)/smoke.serial"

# machine type from first arg passed directly to qemu -M
machine=$1

# Run the test
rm -f ${serial_log}
set +e

timeout -k 1 20 \
qemu-system-ppc64 \
    -bios skiboot.lid \
    -M $machine \
    -m 2g \
    -smp 1 \
    -vga none \
    -monitor none \
    -nographic \
    -serial stdio \
    -kernel binaries/xen \
    |& tee ${serial_log} | sed 's/\r//'

set -e
(grep -q "Hello, ppc64le!" ${serial_log}) || exit 1
exit 0
