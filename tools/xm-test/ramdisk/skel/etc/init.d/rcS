#!/bin/sh

mount -a

# If we're running 2.6, make sure /sys is mounted
if uname -r | grep -q '^2.6'; then
	mount -t sysfs none /sys
fi

# If the block, net, and packet drivers are modules, we need to load them
if test -e /modules/xenblk.ko; then
	insmod /modules/xenblk.ko > /dev/null 2>&1
fi
if test -e /modules/xennet.ko; then
	insmod /modules/xennet.ko > /dev/null 2>&1
fi
if test -e /modules/af_packet.ko; then
	insmod /modules/af_packet.ko > /dev/null 2>&1
fi
