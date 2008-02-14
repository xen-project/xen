#!/bin/sh

ME=$(basename $0)

if [ $# -lt 3 ] ; then
    echo "usage: $ME <linux-build-directory> <linux-arch> <linux-targets...>" 1>&2
    exit 1;
fi

LINUX_DIR=$1
LINUX_ARCH=$2
LINUX_TARGET=$3 # We don't care about second and subsequent targets

case ${XEN_TARGET_ARCH} in
    ia64)
	IMAGE=${LINUX_DIR}/arch/ia64/hp/sim/boot/vmlinux.gz
	;;
    *)
	if [ -f ${LINUX_DIR}/arch/${LINUX_ARCH}/boot/${LINUX_TARGET} ] ; then
	    IMAGE=${LINUX_DIR}/arch/${LINUX_ARCH}/boot/${LINUX_TARGET}
	elif [ -f ${LINUX_DIR}/${LINUX_TARGET} ] ; then
	    IMAGE=${LINUX_DIR}/${LINUX_TARGET}
	else
	    echo "$ME: cannot determine Linux image to use for ${LINUX_ARCH} in ${LINUX_DIR}" 1>&2
	    exit 1
	fi
	;;
esac

echo "$ME: ${IMAGE}" 1>&2
echo ${IMAGE}

exit 0
