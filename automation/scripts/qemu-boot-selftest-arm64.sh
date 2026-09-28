#!/bin/bash

set -ex -o pipefail

# Boot Xen under QEMU with gic-test in xen,xen-bootargs and check that every
# self-test reported OK and that Xen carried on booting.

XEN=binaries/xen
# qemu-system-aarch64 comes from the debian:13-arm64v8 test container, the
# same way the other qemu-smoke-*-arm64 scripts get it.
QEMU=qemu-system-aarch64
DTB_RAW=binaries/virt.dtb
DTB=binaries/virt-bootselftest.dtb
LOG=smoke.serial

NR_CPUS=4

test -f ${XEN}

${QEMU} \
    -machine virt,virtualization=true,gic-version=3,dumpdtb=${DTB_RAW} \
    -cpu cortex-a57 -m 1024 -smp ${NR_CPUS} -display none -net none

cp ${DTB_RAW} ${DTB}
fdtput -t s ${DTB} /chosen xen,xen-bootargs \
    "gic-test console=dtuart sync_console"

rm -f ${LOG}
timeout 60 ${QEMU} \
    -machine virt,virtualization=true,gic-version=3 \
    -cpu cortex-a57 -m 1024 -smp ${NR_CPUS} \
    -serial file:${LOG} \
    -monitor none -display none -no-reboot -net none \
    -dtb ${DTB} \
    -kernel ${XEN} || true

fail=0

check() {
    local what=$1
    local expected=$2
    local got

    got=$(grep -c -- "${what}" ${LOG} || true)
    if [ "${got}" -ne "${expected}" ]; then
        echo "FAIL: '${what}': expected ${expected}, got ${got}"
        fail=1
        return
    fi

    echo "OK: '${what}' x${expected}"
}

# Every CPU sends an SGI to itself...
check "GIC selftest: CPU[0-9]*: SGI to self: OK" ${NR_CPUS}
# ...every secondary CPU sends one to CPU0...
check "GIC selftest: CPU[0-9]*: SGI to CPU0: OK" $((NR_CPUS - 1))
# ...and whichever CPU runs last sends one to all the others.
check "GIC selftest: CPU[0-9]*: SGI to all but self: OK" 1

check "boot self-tests done" ${NR_CPUS}
check "GIC selftest: .*did not receive" 0

# A passing self-test must leave Xen booting normally.
check "LOADING DOMAIN 0\|Xen dom0less mode detected" 1

if [ ${fail} -ne 0 ]; then
    echo "FAILED"
    exit 1
fi

echo "PASSED"
