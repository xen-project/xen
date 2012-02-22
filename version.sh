#!/bin/sh

MAJOR=`grep "export XEN_VERSION" $1 | sed 's/.*=//g' | tr -s " "`
MINOR=`grep "export XEN_SUBVERSION" $1 | sed 's/.*=//g' | tr -s " "`
printf "%d.%d" $MAJOR $MINOR
