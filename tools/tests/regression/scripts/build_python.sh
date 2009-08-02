#!/bin/bash
#
# This script builds python in the dir 
# installed/python-${DEST} from package downloads/Python-{PKG_VERS}.tgz
#

set -e

REG_TEST_DIR=$1
DEST=$2
PKG_VERS=$3

SUB_MAKES_MINUS_J=-j4

BUILD_DIR=${REG_TEST_DIR}/build

mkdir -p ${BUILD_DIR}
(cd ${BUILD_DIR} && tar -xf ${REG_TEST_DIR}/downloads/Python-$PKG_VERS.tgz)
(cd ${BUILD_DIR}/Python-$PKG_VERS &&
 ./configure --enable-shared --enable-ipv6 --without-cxx \
       --with-threads --prefix=${REG_TEST_DIR}/installed/python-$DEST &&
make ${SUB_MAKES_MINUS_J} &&
make install)
rm -fr ${BUILD_DIR}/Python-$PKG_VERS
