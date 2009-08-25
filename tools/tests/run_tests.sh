#!/bin/bash
#
# This runs the available unit-tests with all different supported
# python versions.
# 
# To run this this must be 'cd'ed to the tests directory.
#

ENABLE_UNSUPPORTED=0

function usage()
{
    printf "Usage: %s: [-u]\n" $0
    printf "   -u: run test with unsupported python versions also\n"
}

function run_one_test()
{
    PYTHON=$1
    PYTHON_EXECUTABLE=`echo $PYTHON | tr -d "-"`
    echo "+++ Running tests with $PYTHON"
    export LD_LIBRARY_PATH=./regression/installed/$PYTHON/lib
    ./regression/installed/$PYTHON/bin/$PYTHON_EXECUTABLE \
	utests/run_all_tests.py
    echo "--- Finished tests with $PYTHON"
}

function run_all_tests()
{
    for PYTHON in $@;
    do
	run_one_test $PYTHON
    done
}

while getopts u name
do
    case $name in
	h)  usage; exit 0;;
	u)  ENABLE_UNSUPPORTED=1;;
	?)  usage; exit 2;;
    esac
done

# Build the different python versions
(cd regression && make -j4 runtime-environment)

# Supported: when an unit test fails this should be seen as an error
PYTHON_SUPPORTED="python-2.4 python-2.5 python-2.6"
# Unsupported: failure should be seen as a hint
PYTHON_UNSUPPORTED="python-3.1"

export PYTHONPATH=`echo $PWD/../python/build/lib.*`:$PWD

set -e
run_all_tests $PYTHON_SUPPORTED

if test $ENABLE_UNSUPPORTED -eq 1
then
    run_all_tests $PYTHON_UNSUPPORTED
fi
