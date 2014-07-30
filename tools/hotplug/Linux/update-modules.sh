#!/usr/bin/env bash

set -e

IFS=''

XEN_ROOT=$1
XEN_OS=$2
XENCOMMONS_INITD=$3

cat  $XEN_ROOT/config/${XEN_OS}.modules	| (
	while read l ; do
		if echo $l | egrep -q "^#" ; then
			continue
		fi
		if echo "$l" | egrep -q "\|" ; then
			m1=${l%%|*}
			m2=${l#*|}
			echo "        modprobe $m1 2>/dev/null || modprobe $m2 2>/dev/null"
		else
			echo "        modprobe $l 2>/dev/null"
		fi
	done
) > ${XENCOMMONS_INITD}.modules

cat  ${XENCOMMONS_INITD}.in	| (
	while read l ; do
		if echo "$l" | egrep -q "@LOAD_MODULES@" ; then
			cat ${XENCOMMONS_INITD}.modules
		else
			echo $l
		fi
	done
)

rm -f ${XENCOMMONS_INITD}.modules
