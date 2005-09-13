#!/bin/sh

#
# Doxyfilter <source-root> <filename>
#

dir=$(dirname "$0")

PYFILTER="$dir/pythfilter.py"

if [ "${2/.py/}" != "$2" ]
then
    python "$PYFILTER" -r "$1" -f "$2"
else
    cat "$2"
fi
