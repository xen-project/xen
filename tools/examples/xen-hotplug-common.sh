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


dir=$(dirname "$0")
. "$dir/xen-script-common.sh"

exec 2>>/var/log/xen-hotplug.log

export PATH="/sbin:/bin:/usr/bin:/usr/sbin:$PATH"
export LANG="POSIX"
unset $(set | grep ^LC_ | cut -d= -f1)

log() {
  local level="$1"
  shift
  logger -p "daemon.$level" -- "$0:" "$@" || echo "$0 $@" >&2
}

fatal() {
  xenstore_write "$XENBUS_PATH"/hotplug-status error
  log err "$@"
  exit 1
}

success() {
  # Tell DevController that backend is "connected"
  xenstore_write "$XENBUS_PATH"/hotplug-status connected
}

do_or_die() {
  "$@" || fatal "$@ failed"
}

sigerr() {
  fatal "$0 failed; error detected."
}

trap sigerr ERR


##
# xenstore_read <path>+
#
# Read each of the given paths, returning each result on a separate line, or
# exit this script if any of the paths is missing.
#
xenstore_read() {
  local v=$(xenstore-read "$@" || true)
  [ "$v" != "" ] || fatal "xenstore-read $@ failed."
  echo "$v"
}


##
# xenstore_read_default <path> <default>
#
# Read the given path, returning the value there or the given default if the
# path is not present.
#
xenstore_read_default() {
  xenstore-read "$1" || echo "$2"
}


##
# xenstore_write (<path> <value>)+
#
# Write each of the key/value pairs to the store, and exit this script if any
# such writing fails.
#
xenstore_write() {
  log debug "Writing $@ to xenstore."
  xenstore-write "$@" || fatal "Writing $@ to xenstore failed."
}


#
# Serialisation
#

LOCK_SLEEPTIME=1
LOCK_SPINNING_RETRIES=5
LOCK_RETRIES=10
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


_claim_lock()
{
  local lockdir="$1"
  local owner=$(_lock_owner "$lockdir")
  local retries=0

  while expr $retries '<' $LOCK_RETRIES
  do
    mkdir "$lockdir" && trap "release_lock $1; sigerr" ERR &&
      _update_lock_info "$lockdir" && return

    local new_owner=$(_lock_owner "$lockdir")
    if [ "$new_owner" != "$owner" ]
    then
      owner="$new_owner"
      retries=0
    fi

    if expr $retries '>' $LOCK_SPINNING_RETRIES
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
  rm -rf "$1" || true
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


log debug "$@" "XENBUS_PATH=$XENBUS_PATH"
