#!/bin/sh

opt_full=false
while [ $# -gt 1 ]; do
    case "$1" in
        --full) opt_full=true ;;
        *) break ;;
    esac
    shift
done

MAJOR=`grep "export XEN_VERSION" $1 | sed 's/.*=//g' | tr -s " "`
MINOR=`grep "export XEN_SUBVERSION" $1 | sed 's/.*=//g' | tr -s " "`

if $opt_full; then
    extraversion=$(grep "export XEN_EXTRAVERSION" $1 | sed 's/^.* ?=\s\+//; s/\$([^)]*)//g; s/ //g')
    : ${XEN_EXTRAVERSION:=${extraversion}${XEN_VENDORVERSION}}
else
    unset XEN_EXTRAVERSION
fi
printf "%d.%d%s" $MAJOR $MINOR $XEN_EXTRAVERSION
