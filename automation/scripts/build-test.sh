#!/bin/bash

# Run command on every commit within the range specified. If no command is
# provided, use the default one to clean and build the whole tree.
#
# The default rune is rather simple. To do a cross-build, please put your usual
# build rune in a shell script and invoke it with this script.
#
# Set NON_SYMBOLIC_REF=1 if you want to use this script in detached HEAD state.
# This is currently used by automated test system.

# Colors with ANSI escape sequences
txt_info='[32m'
txt_err='[31m'
txt_clr='[0m'

# $GITLAB_CI should be "true" or "false".
if [ "$GITLAB_CI" != true ]; then
    GITLAB_CI=false
fi

gitlab_log_section() {
    if $GITLAB_CI; then
        echo -n "[0Ksection_$1:$(date +%s):$2[0K"
    fi
    if [ $# -ge 3 ]; then
        echo "$3"
    fi
}
log_section_last=
log_section_start() {
    log_section_last="${1%\[collapsed=true\]}"
    gitlab_log_section 'start' "$1" "${txt_info}$2${txt_clr}"
}
log_section_end() {
    if [ "$log_section_last" ]; then
        gitlab_log_section 'end' "$log_section_last"
        log_section_last=
    fi
}


if test $# -lt 2 ; then
    echo "Usage:"
    echo " $0 <BASE> <TIP> [CMD]"
    echo " If [CMD] is not specified, run the default command"
    echo "     git clean -fdx && ./configure && make -j4"
    exit 1
fi

pushd `git rev-parse --show-toplevel`

if ! $GITLAB_CI; then
    status=`git status -s`
    if test -n "$status"; then
        echo "Tree is dirty, aborted"
        exit 1
    fi
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
    log_section_start "commit_$rev[collapsed=true]" "Testing #$num $(git log -1 --abbrev=12 --format=tformat:'%h ("%s")' $rev)"

    git checkout $rev
    ret=$?
    if test $ret -ne 0; then
        log_section_end
        echo "${txt_err}Failed to checkout $num $rev with $ret${txt_clr}"
        break
    fi

    if test $# -eq 0 ; then
        git clean -fdx && ./configure && make -j4
    elif $GITLAB_CI; then
        "$@" > "build-$num.log" 2>&1
    else
        "$@"
    fi
    ret=$?
    if test $ret -ne 0; then
        if $GITLAB_CI; then
            cat "build-$num.log"
        fi
        log_section_end
        echo "${txt_err}Failed at $num $rev with $ret${txt_clr}"
        break
    fi
    echo
    log_section_end
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
