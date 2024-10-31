#!/bin/sh

if test $# -lt 3; then
	echo "Usage: $0 <tree> <committish> <dir>"
	exit 1
fi

TREE=$1
COMMITTISH=$2
DIR=$3

set -e

if test \! -d $DIR-remote; then
	rm -rf $DIR-remote $DIR-remote.tmp
	mkdir -p $DIR-remote.tmp; rmdir $DIR-remote.tmp
	$GIT clone $TREE $DIR-remote.tmp
	if test "$COMMITTISH" ; then
		cd $DIR-remote.tmp
		$GIT fetch origin "$COMMITTISH"
		$GIT branch -D dummy >/dev/null 2>&1 ||:
		$GIT checkout -b dummy FETCH_HEAD
		cd -
	fi
	mv $DIR-remote.tmp $DIR-remote
fi
rm -f $DIR
ln -sf $(basename $DIR-remote) $DIR
