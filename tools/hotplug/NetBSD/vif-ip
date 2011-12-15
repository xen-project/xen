#!/bin/sh -e

# $NetBSD: vif-ip-nbsd,v 1.1.1.1 2008/08/07 20:26:57 cegger Exp $
# Called by xenbackendd
# Usage: vif-ip xsdir_backend_path state

DIR=$(dirname "$0")
. "${DIR}/hotplugpath.sh"

PATH=${BINDIR}:${SBINDIR}:${LIBEXEC}:${PRIVATE_BINDIR}:/bin:/usr/bin:/sbin:/usr/sbin
export PATH

xpath=$1
xstatus=$2

case $xstatus in
6)
	# device removed
	xenstore-rm $xpath
	exit 0
	;;
2)
	xip=$(xenstore-read "$xpath/ip")
	xfid=$(xenstore-read "$xpath/frontend-id")
	xhandle=$(xenstore-read "$xpath/handle")
	iface=$(xenstore-read "$xpath/vifname")
	ifconfig $iface $xip up
	xenstore-write $xpath/hotplug-status connected
	exit 0
	;;
*)
	exit 0
	;;
esac
