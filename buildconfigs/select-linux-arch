#!/bin/sh

ME=$(basename $0)

if [ $# -lt 1 ] || [ $# -gt 2 ] ; then
    echo "usage: $ME <linux-build-directory>" 1>&2
    exit 1;
fi

LINUX_DIR=$1

case ${XEN_TARGET_ARCH} in
    x86_32|x86_64)
	if [ -d ${LINUX_DIR}/arch/x86 ] ; then
	    ARCH=x86
	elif [ "${XEN_TARGET_ARCH}" = "x86_32" ] ; then
	    ARCH=i386
	else
	    ARCH=x86_64
	fi
	;;
    *)
	ARCH=${XEN_TARGET_ARCH}
	;;
esac

echo "$ME: ${ARCH}" 1>&2
echo ${ARCH}

exit 0
