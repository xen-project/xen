#!/bin/bash
#
# Copyright (C) 2008 Oracle Corporation and/or its affiliates.
# All rights reserved.
# Written by: Dan Magenheimer <dan.magenheimer@oracle.com>
#
# xenballoond - In-guest engine for Xen memory ballooning
# Original version: 080630
# Updated 0906XX: add tmem preswap auto-shrinking
#
# Two self-ballooning "policies" are implemented:
# - Selfballooning: Adjust memory periodically, with no (or little) input
#     from domain0.  Target memory is determined solely by the
#     Committed_AS line in /proc/meminfo, but parameters may adjust
#     the rate at which the target is achieved.
# - Directed ballooning: Adjust memory solely as directed by domain0
#
# Under some circumstances, "output" may also be generated; the contents
# of /proc/meminfo and /proc/vmstat may be periodically placed on xenbus.
#
# If xenbus is running and the /usr/bin/xenstore-* tools are installed,
# "xenbus is enabled".
#
# Parameters are documented in <SYSCONFIG>/xenballoon.conf. Although
# some are not used with directed ballooning, all must be set properly.
# If xenbus is enabled, some of these parameters may be overridden by values
# set by domain0 via xenbus.

minmb() {
	RETVAL=$XENBALLOON_MINMEM
	if [ $RETVAL -ne 0 ]; then
		return $RETVAL
	fi
	kb=`cat $XENBALLOON_MAXMEMFILE`
	let "mb=$kb/1024"
	let "pages=$kb/4"
	# this algorithm from drivers/xen/balloon/balloon.c:minimum_target()
	# which was added to balloon.c in 2008 to avoid ballooning too small
	# it is unnecessary here except to accomodate pre-2008 balloon drivers
	# note that ranges are adjusted because a VM with "memory=1024"
	# gets somewhat less than 1024MB
	if [ $mb -lt 125 ]; then
		let RETVAL="$(( 8 + ($pages >> 9) ))"
	elif [ $mb -lt 500 ]; then
		let RETVAL="$(( 40 + ($pages >> 10) ))"
	elif [ $mb -lt 2000 ]; then
		let RETVAL="$(( 104 + ($pages >> 11) ))"
	else
		let RETVAL="$(( 296 + ($pages >> 13) ))"
	fi
	return	# value returned in RETVAL in mB
}

curkb() {
	kb=`grep MemTotal /proc/meminfo | sed 's/  */ /' | \
		cut -f2 -d' '`
	RETVAL=$kb
	return  # value returned in RETVAL in kB
}

downhysteresis() {
	RETVAL=$XENBALLOON_AUTO_DOWNHYSTERESIS
	if [ $xenstore_enabled = "true" ]; then
		if xenstore-exists memory/downhysteresis ; then
			RETVAL=`xenstore-read memory/downhysteresis`
		fi
	fi
	return
}

uphysteresis() {
	RETVAL=$XENBALLOON_AUTO_UPHYSTERESIS
	if [ $xenstore_enabled = "true" ]; then
		if xenstore-exists memory/uphysteresis ; then
			RETVAL=`xenstore-read memory/uphysteresis`
		fi
	fi
	return
}

selfballoon_eval() {
	if [ $xenstore_enabled = "true" ]; then
		if xenstore-exists memory/selfballoon; then
			RETVAL=`xenstore-read memory/selfballoon`
			if [ $RETVAL -eq 1 ]; then
				selfballoon_enabled=true
				return
			fi
		fi
	fi
	selfballoon_enabled=$XENBALLOON_SELF
	return
}

selftarget() {
	tgtkb=`grep Committed_AS /proc/meminfo | sed 's/  */ /' | cut -f2 -d' '`
	minmb
	let "minbytes=$RETVAL*1024*1024"
	let "tgtbytes=$tgtkb*1024"
	if [ $tgtbytes -lt $minbytes ]; then
		let "tgtbytes=$minbytes"
	fi
	RETVAL=$tgtbytes  # value returned in RETVAL in bytes
	return
}

# $1 == 1 means use selftarget, else target in kB
balloon_to_target() {
	if [ "$1" -eq 1 ]; then
		selftarget
		tgtbytes=$RETVAL
	else
		let "tgtbytes=$(( $1 * 1024 ))"
	fi
	curkb
	let "curbytes=$RETVAL*1024"
	if [ $curbytes -gt $tgtbytes ]; then
		downhysteresis
		downhys=$RETVAL
		if [ $downhys -ne 0 ]; then
			let "tgtbytes=$(( $curbytes - \
				( ( $curbytes - $tgtbytes ) / $downhys ) ))"
		fi
	else if [ $curbytes -lt $tgtbytes ]; then
		uphysteresis
		uphys=$RETVAL
		let "tgtbytes=$(( $curbytes + \
				( ( $tgtbytes - $curbytes ) / $uphys ) ))"
		fi
	fi
	echo $tgtbytes > /proc/xen/balloon
	if [ $xenstore_enabled = "true" ]; then
		let "tgtkb=$(( $tgtbytes/1024 ))"
		xenstore-write memory/selftarget $tgtkb
	fi
}

send_memory_stats() {
	if [ ! $xenstore_enabled = "true" ]; then
		return
	fi
	if [ $XENBALLOON_SEND_MEMINFO ]; then
		xenstore-write memory/meminfo "`cat /proc/meminfo`"
	fi
	if [ $XENBALLOON_SEND_VMSTAT ]; then
		xenstore-write memory/vmstat "`cat /proc/vmstat`"
	fi
	if [ $XENBALLOON_SEND_UPTIME ]; then
		xenstore-write memory/uptime "`cat /proc/uptime`"
	fi
}


curpreswappages() {
	pages=$(cat $XENBALLOON_PRESWAP_SYSFILE)
	RETVAL=$pages
	return  # value returned in RETVAL in pages
}

preswaphysteresis() {
	RETVAL=$XENBALLOON_PRESWAP_HYSTERESIS
	if [ $xenstore_enabled = "true" ]; then
		if xenstore-exists memory/preswaphysteresis ; then
			RETVAL=`xenstore-read memory/preswaphysteresis`
		fi
	fi
	return
}

preswapinertia() {
	RETVAL=$XENBALLOON_PRESWAP_INERTIA
	if [ $xenstore_enabled = "true" ]; then
		if xenstore-exists memory/preswapinertia ; then
			RETVAL=`xenstore-read memory/preswapinertia`
		fi
	fi
	return
}

send_preswap_stats() {
	if [ ! $xenstore_enabled = "true" ]; then
		return
	fi
	curpreswappages
	preswap_pgs=$RETVAL
	if [ $XENBALLOON_SEND_PRESWAP ]; then
		xenstore-write memory/preswap "$preswap_pgs"
	fi
}

shrink_preswap() {
	if [ "$XENBALLOON_PRESWAP_SHRINK" = "false" ]; then
		return
	fi
	if [ ! -f "$XENBALLOON_PRESWAP_SYSFILE" ]; then
		return
	fi
	curpreswappages
	preswaplast=$preswapnow
	preswapnow=$RETVAL
	if [ $preswapnow -eq 0 -o $preswapnow -ne $preswaplast ]; then
		preswapinertia
		preswapinertiacounter=$RETVAL
		return
	fi
	let "preswapinertiacounter=$preswapinertiacounter-1"
	if [ $preswapinertiacounter -ne 0 ]; then
		return
	fi
	preswaphysteresis
	preswaphys=$RETVAL
	if [ $preswaphys -eq 0 ]; then
		return
	fi
	let "tgtpreswappages=$(( $preswapnow - \
				( $preswapnow / $preswaphys ) ))"
	preswapinertia
	preswapinertiacounter=$RETVAL
	echo $tgtpreswappages > "$XENBALLOON_PRESWAP_SYSFILE"
}

if [ ! -f /proc/xen/balloon ]; then
	echo "$0: no balloon driver installed"
	exit 0
fi
if [ ! -f /proc/meminfo ]; then
	echo "$0: can't read /proc/meminfo"
	exit 0
fi
xenstore_enabled=true
if [ -f /usr/bin/xenstore-exists -a -f /usr/bin/xenstore-read -a \
     -f /usr/bin/xenstore-write ]; then
	xenstore_enabled=true
else
	echo "$0: missing /usr/bin/xenstore-* tools, disabling directed ballooning"
	xenstore_enabled=false
fi
preswapnow=0

# See docs/misc/distro_mapping.txt
if [ -f /etc/sysconfig/xenballoon.conf ]; then
	. /etc/sysconfig/xenballoon.conf
elif [ -f /etc/default/xenballoon.conf ]; then
	. /etc/default/xenballoon.conf
fi

while true;
do
	# handle special case for PV domains with hot-add memory
	if [ ! -f $XENBALLOON_MAXMEMFILE ]; then
		maxkb=0
	else
		maxkb=`cat $XENBALLOON_MAXMEMFILE`
	fi
	curkb=`grep MemTotal /proc/meminfo | sed 's/  */ /' | cut -f2 -d' '`
	if [ $curkb -gt $maxkb ]; then
		echo $curkb > $XENBALLOON_MAXMEMFILE
	fi
	interval=$XENBALLOON_INTERVAL
	# do self-ballooning
	selfballoon_eval
	if [ $selfballoon_enabled = "true" ]; then
		balloon_to_target 1
		interval=$XENBALLOON_SELF_INTERVAL
	# or do directed ballooning
	elif [ $xenstore_enabled = "true" ]; then
		if xenstore-exists memory/target ; then
			tgtkb=`xenstore-read memory/target`
			balloon_to_target $tgtkb
		fi
		interval=$XENBALLOON_INTERVAL
	fi
	shrink_preswap
	send_memory_stats
	send_preswap_stats
	if [ $xenstore_enabled = "true" ]; then
		if xenstore-exists memory/interval ; then
			interval=`xenstore-read memory/interval`
		fi
	fi
	sleep $interval
done &

