#!/bin/bash

set -ex -o pipefail

serial_log="$(pwd)/smoke.serial"

# machine type from first arg passed directly to qemu -M
machine=$1

# Run the test
rm -f ${serial_log}

export TEST_CMD="qemu-system-ppc64 \
    -bios skiboot.lid \
    -M $machine \
    -m 2g \
    -smp 1 \
    -vga none \
    -monitor none \
    -nographic \
    -serial stdio \
    -kernel binaries/xen"

export TEST_LOG="${serial_log}"
export PASSED="Hello, ppc64le!"

./automation/scripts/console.exp | sed 's/\r\+$//'
