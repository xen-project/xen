#!/bin/sh
# usage:
#  .../install-wrap $(PYTHON_PATH) install <options-to-install> <src>... <dest>
# where
#  PYTHON_PATH is what to put after #! and may be `/usr/bin/env python'
#
# Used via $(INSTALL_PYTHON_PROG) in Rules.mk; PYTHON_PATH comes from $(PYTHON)

set -e
if test $# -lt 2; then
	echo >&2 "${0##*/}: too few arguments"
	exit 1
fi

pythonpath="$1"
shift

install="$1"
shift
srcs=""

while [ $# != 0 ]; do
	case "$1" in
	-|--)	install=`echo "${install} $1"`
		shift
		break
		;;
	-*)	install=`echo "${install} $1"`
		shift
		;;
	*)	break
		;;
	esac
done

while test $# -gt 1; do
	srcs=`echo "${srcs} $1"`
	shift
done

dest="$1"
shift

destf="$dest"
for srcf in ${srcs}; do
	if test -d "$dest"; then
		destf="$dest/${srcf%%*/}"
	fi
	org="$(sed -n '2q; /^#! *\/usr\/bin\/env python *$/p' $srcf)"
	if test "x$org" = x; then
		eval "${install} $srcf $destf"
		continue
	fi
	tmpf="$destf.tmp"
	eval "${install} $srcf $tmpf"
	printf >"$tmpf" "#!%s\n" "$pythonpath"
	sed -e 1d "$srcf" >>"$tmpf"
	mv -f "$tmpf" "$destf"
done
exit 0
