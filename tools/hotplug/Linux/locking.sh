#
# Copyright (c) 2005 XenSource Ltd.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

#
# Serialisation
#

LOCK_SLEEPTIME=1
LOCK_SPINNING_RETRIES=5
LOCK_RETRIES=100
LOCK_BASEDIR=/var/run/xen-hotplug


claim_lock()
{
  local lockdir="$LOCK_BASEDIR/$1"
  mkdir -p "$LOCK_BASEDIR"
  _claim_lock "$lockdir"
}


release_lock()
{
  _release_lock "$LOCK_BASEDIR/$1"
}


# This function will be redefined in xen-hotplug-common.sh.
sigerr() {
  exit 1
}


_claim_lock()
{
  local lockdir="$1"
  local owner=$(_lock_owner "$lockdir")
  local retries=0

  while [ $retries -lt $LOCK_RETRIES ]
  do
    mkdir "$lockdir" 2>/dev/null && trap "_release_lock $lockdir; sigerr" ERR &&
      _update_lock_info "$lockdir" && return

    local new_owner=$(_lock_owner "$lockdir")
    if [ "$new_owner" != "$owner" ]
    then
      owner="$new_owner"
      retries=0
    fi

    if [ $retries -gt $LOCK_SPINNING_RETRIES ]
    then
      sleep $LOCK_SLEEPTIME
    else
      sleep 0
    fi
    retries=$(($retries + 1))
  done
  _steal_lock "$lockdir"
}


_release_lock()
{
  trap sigerr ERR
  rm -rf "$1" 2>/dev/null || true
}


_steal_lock()
{
  local lockdir="$1"
  local owner=$(cat "$lockdir/owner" 2>/dev/null || echo "unknown")
  log err "Forced to steal lock on $lockdir from $owner!"
  _release_lock "$lockdir"
  _claim_lock "$lockdir"
}


_lock_owner()
{
  cat "$1/owner" 2>/dev/null || echo "unknown"
}


_update_lock_info()
{
  echo "$$: $0" >"$1/owner"
}
