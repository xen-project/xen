#!/bin/bash

# Hide every xen-syms linking pass except LAST_LINKING_PASS.
# The pass list is the foreach in xen/scripts/Makefile.link.

set -e

cd "$(dirname "$0")"
arch=$(echo "${XEN_TARGET_ARCH}" | sed -e 's/x86.*/x86/' -e 's/arm.*/arm/')
last=$(sed -n 's/^LAST_LINKING_PASS *:= *\([0-9]\).*/\1/p' \
    "../../../xen/arch/${arch}/Makefile" | head -n 1)
passes=$(sed -n 's/.*foreach n,\([0-9 ]*\).*/\1/p' \
    ../../../xen/scripts/Makefile.link | head -n 1)
test -n "${last}"
test -n "${passes}"
hidden=$(printf '%s' "${passes}" | tr -d " ${last}")

printf '%s\n' \
    "-file_tag+={xen_syms_tmp, \"^xen/\\\\.xen-syms\\\\.[${hidden}]\$\"}" \
    >xen-syms-passes.ecl
