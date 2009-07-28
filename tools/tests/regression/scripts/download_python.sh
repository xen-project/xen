#!/bin/bash
#
# Downloads python with version $1 and stores in into the downloads dir.
#

set -e

XEN_ROOT=$1
VERSION=$2

mkdir -p ${XEN_ROOT}/tests/downloads
wget -q -O ${XEN_ROOT}/tests/downloads/Python-${VERSION}.tgz http://www.python.org/ftp/python/${VERSION}/Python-${VERSION}.tgz
