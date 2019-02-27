#!/bin/bash

# Run command on every commit within the range specified. If no command is
# provided, use the default one to clean and build the whole tree.
#
# The default rune is rather simple. To do a cross-build, please put your usual
# build rune in a shell script and invoke it with this script.
#
# Set NON_SYMBOLIC_REF=1 if you want to use this script in detached HEAD state.
# This is currently used by automated test system.

if test $# -lt 2 ; then
    echo "Usage:"
    echo " $0 <BASE> <TIP> [CMD]"
    echo " If [CMD] is not specified, run the default command"
    echo "     git clean -fdx && ./configure && make -j4"
    exit 1
fi

pushd `git rev-parse --show-toplevel`

status=`git status -s`
if test -n "$status"; then
    echo "Tree is dirty, aborted"
    exit 1
fi

BASE=$1; shift
TIP=$1; shift

if [[ "_${NON_SYMBOLIC_REF}" != "_1" ]]; then
    ORIG=`git symbolic-ref -q --short HEAD`
    if test $? -ne 0; then
        echo "Detached HEAD, aborted"
        exit 1
    fi
else
    ORIG=`git rev-parse HEAD`
fi

ret=1
while read num rev; do
    echo "Testing $num $rev"

    git checkout $rev
    ret=$?
    if test $ret -ne 0; then
        echo "Failed to checkout $num $rev with $ret"
        break
    fi

    if test $# -eq 0 ; then
        git clean -fdx && ./configure && make -j4
    else
        "$@"
    fi
    ret=$?
    if test $ret -ne 0; then
        echo "Failed at $num $rev with $ret"
        break
    fi
    echo
done < <(git rev-list $BASE..$TIP | nl -ba | tac)

echo "Restoring original HEAD"
git checkout $ORIG
gco_ret=$?
if test $gco_ret -ne 0; then
    echo "Failed to restore orignal HEAD. Check tree status before doing anything else!"
    exit $gco_ret
fi

if test $ret -eq 0; then
    echo "ok."
fi
exit $ret
