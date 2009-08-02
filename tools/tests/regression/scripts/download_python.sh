#!/bin/bash
#
# Downloads python with version $1 and stores in into the downloads dir.
#

set -e

REG_TEST_DIR=$1
VERSION=$2

mkdir -p ${REG_TEST_DIR}/downloads
wget -q -O ${REG_TEST_DIR}/downloads/Python-${VERSION}.tgz http://www.python.org/ftp/python/${VERSION}/Python-${VERSION}.tgz
