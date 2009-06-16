#!/bin/bash
#
# xenballoon-monitor - monitor certain stats from xenballoond
#   (run in dom0 with "watch -d xenballoon-monitor" for xentop-like output)
# updated 090610 to include tmem stats
#
# Copyright (C) 2009 Oracle Corporation and/or its affiliates.
# All rights reserved
# Written by: Dan Magenheimer <dan.magenheimer@oracle.com>
#
# Hint: Use "xm sched-credit -d 0 -w 2000" to watch on heavily loaded machines
#
TMEMTMP=$(/bin/mktemp -q /tmp/xenballoon-monitor.XXXXXX)
echo "id   mem-kb  tgt-kb  commit  swapin swapout    pgin    pgout  preswap  precache"
for i in `xenstore-list /local/domain`; do
 if [ "$i" -ne 0 ]; then
 tot=0; tgt=0; sin=0; sout=0; pgin=0; pgout=0; cmt=0; up=0; idle=0;
 act=0; preswap=0; precache=0
 if xenstore-exists /local/domain/$i/memory/meminfo; then
  tot=`xenstore-read /local/domain/$i/memory/meminfo | grep MemTotal \
   | sed 's/[^1-9]*\([1-9][0-9]*\).*/\1/'`
  cmt=`xenstore-read /local/domain/$i/memory/meminfo | grep Committed_AS \
   | sed 's/[^1-9]*\([1-9][0-9]*\).*/\1/'`
 fi
 if xenstore-exists /local/domain/$i/memory/selftarget; then
  tgt=`xenstore-read /local/domain/$i/memory/selftarget`
 fi
 if xenstore-exists /local/domain/$i/memory/vmstat; then
  sin=$(xenstore-read /local/domain/$i/memory/vmstat | tr '\\\n' '\n' \
	| grep pswpin | cut -d" " -f2)
  sout=$(xenstore-read /local/domain/$i/memory/vmstat | tr '\\\n' '\n' \
	| grep pswpout | cut -d" " -f2)
  pgin=$(xenstore-read /local/domain/$i/memory/vmstat | tr '\\\n' '\n' \
	| grep pgpgin | cut -d" " -f2)
  pgout=$(xenstore-read /local/domain/$i/memory/vmstat | tr '\\\n' '\n' \
	| grep pgout | cut -d" " -f2)
 fi
 xm tmem-list --all --long > $TMEMTMP
 precache=`grep "C=CI:$i" $TMEMTMP | sed 's/C=CI.*Ec:\([0-9][0-9]*\).*/\1/'`
 if xenstore-exists /local/domain/$i/memory/preswap; then
  preswap=`xenstore-read /local/domain/$i/memory/preswap`
  printf "%2d %8d%8d%8d%7d%8d%9d%9d%9d%9d\n" $i $tot $tgt $cmt $sin $sout $pgin $pgout $preswap $precache
 else
  printf "%2d %8d%8d%8d%9d%9d%10d%10d\n" $i $tot $tgt $cmt $sin $sout $pgin $pgout
 fi
 fi
done
echo -n Free memory: `xm info | grep free | sed 's/[^1-9]*\([1-9][0-9]*\).*/\1/'` MiB "  "
tmem_free_pages=`grep "G=" $TMEMTMP | sed 's/G=.*Ta:\([0-9][0-9]*\).*/\1/'`
if [ ! -z "$tmem_free_pages" ]; then
 let "tmem_free_mb=$tmem_free_pages/256"
 echo -n Idle tmem: $tmem_free_mb MiB "  "
fi
tmem_eph_pages=`grep "G=" $TMEMTMP | sed 's/G=.*Ec:\([0-9][0-9]*\).*/\1/'`
if [ ! -z "$tmem_eph_pages" ]; then
 let "tmem_eph_mb=$tmem_eph_pages/256"
 echo -n Ephemeral tmem: $tmem_eph_mb MiB
fi
echo ""
