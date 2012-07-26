#!/bin/sh

ME=$(basename $0)

if [ $# -lt 1 ] || [ $# -gt 2 ] ; then
    echo "usage: $ME <repository-name> [search-path]" 1>&2
    exit 1;
fi

REPO=$1
LINUX_SRC_PATH=$2

if [ X"${LINUX_SRC_PATH}" != X ] ; then
    echo "$ME: Searching \`${LINUX_SRC_PATH}' for $REPO" 1>&2
    IFS_saved="$IFS"
    IFS=:
    for i in $LINUX_SRC_PATH ; do
	# Ignore current directory since we will almost certainly find
	# the target directory there which breaks updating (there's no
	# point updating from yourself!).
	if [ X"." = X"${i}" ] ; then
	    echo "$ME: Ignoring \`.'" 1>&2
	    continue
	fi

	if [ -d "$i/$REPO/.hg" ] ; then
	    echo "$ME: Found $i/$REPO" 1>&2
	    echo "$i/$REPO"
	    exit 0
	fi
    done
    IFS="$IFS_saved"
fi

if [ -d ${XEN_ROOT}/.hgxxx ] ; then
    XEN=$(hg -R ${XEN_ROOT} path default)
    if [ $? -ne 0 ] || [ X"$XEN" = "X" ] ; then
	echo "$ME: Unable to determine Xen repository parent." 1>&2
	exit 1;
    fi

    BASE=$(dirname ${XEN})
    if [ $? -ne 0 ] || [ X"$BASE" = "X" ] ; then
	echo "$ME: Unable to determine Xen repository base." 1>&2
	exit 1;
    fi
    if [ -d "$XEN" ] && [ ! -d "$BASE/$REPO" ] ; then
	echo "$ME: No such dir: $BASE/$REPO" 1>&2
	exit 1
    fi

    echo "$ME: Found ${BASE}/${REPO}" 1>&2

    # If ${BASE}/${REPO} is a local directory then prepend file:// so that
    # the test in src.hg-clone will fail and we will clone instead of
    # linking this repository. We only want to link repositories which
    # were found via LINUX_SRC_PATH.
    if [ -d "${BASE}/${REPO}" ] ; then
	echo "file://${BASE}/${REPO}"
    else
	echo ${BASE}/${REPO}
    fi
else
    echo "Unable to determine path to Linux source tree." 1>&2
    echo "Falling back to linux-2.6.18-xen Mercurial repository." 1>&2
    echo http://xenbits.xen.org/linux-2.6.18-xen.hg
fi

exit 0
