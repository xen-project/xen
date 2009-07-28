#!/bin/bash
#
# Checks the syntax of all .py files
# (compiles them into .pyc files)
#

XEN_ROOT=$1
p=$2

echo "Syntax check for $p"
PYTHON_EXECUTABLE=`echo $p | tr -d "-"`
export LD_LIBRARY_PATH=${XEN_ROOT}/tests/installed/$p/lib
export PATH=${XEN_ROOT}/tests/installed/$p/bin:$PATH
# -m is available starting with python 2.4
# When support for 2.3 (and earlier) is dropped,
# the following line will do.
# ${PYTHON_EXECUTABLE} -m compileall -f -q -x ".*\.hg.*|^\.\./tests/installed.*" ..
${PYTHON_EXECUTABLE} ${XEN_ROOT}/tests/installed/$p/lib/${PYTHON_EXECUTABLE}/compileall.py -f -q -x ".*\.hg.*|.*/tests/installed.*" ..
exit $?
