#!/bin/bash
#
# XTF test runner (QEMU).
#

set -e -o pipefail

if [ $# -lt 3 ]; then
    echo "Usage: $(basename $0) ARCH XTF-VARIANT XTF-NAME"
    exit 0
fi

export ARCH="$1"
shift

set -x

export XEN_ROOT="${PWD}"
cd $(dirname $0)

source include/xtf-runner

if [ ! -f "include/xtf-${ARCH}" ]; then
    die "unsupported architecture '${ARCH}'"
fi
source include/xtf-${ARCH}

xtf_test $@
