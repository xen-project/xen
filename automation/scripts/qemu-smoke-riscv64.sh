#!/bin/bash

set -ex

# Run the test
rm -f smoke.serial
set +e

export QEMU_CMD="qemu-system-riscv64 \
    -M virt \
    -smp 1 \
    -nographic \
    -m 2g \
    -kernel binaries/xen"

export QEMU_LOG="smoke.serial"
export PASSED="All set up"

./automation/scripts/qemu-key.exp
