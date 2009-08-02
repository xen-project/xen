#!/bin/bash
#
# Checks the syntax of all .py files
# (compiles them into .pyc files)
#

REG_TEST_DIR=$1
# Python version, e.g. python-2.3
PYTHON=$2
PATH_TO_CHECK=$3

echo "Syntax check for $PYTHON"
PYTHON_EXECUTABLE=`echo $PYTHON | tr -d "-"`
export LD_LIBRARY_PATH=${REG_TEST_DIR}/installed/$PYTHON/lib
export PATH=${REG_TEST_DIR}/installed/$PYTHON/bin:$PATH

# -m is available starting with python 2.4
# When support for 2.3 (and earlier) is dropped,
# the following line will do.
# ${PYTHON_EXECUTABLE} -m compileall -f -q -x ".*\.hg.*|.*/tools/tests/regression/installed.*" ${PATH_TO_CHECK}
${PYTHON_EXECUTABLE} ${REG_TEST_DIR}/installed/$PYTHON/lib/${PYTHON_EXECUTABLE}/compileall.py -f -q -x ".*\.hg.*|.*/installed/python-.*" ${PATH_TO_CHECK}
exit $?
