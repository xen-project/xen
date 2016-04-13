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
# License along with this library; If not, see <http://www.gnu.org/licenses/>.
#


dir=$(dirname "$0")
. "$dir/xen-hotplug-common.sh"

findCommand "$@"

if [ "$command" != "add" ] &&
   [ "$command" != "remove" ]
then
  log err "Invalid command: $command"
  exit 1
fi


XENBUS_PATH="${XENBUS_PATH:?}"


ebusy()
{
  xenstore_write "$XENBUS_PATH/hotplug-error" "$*" \
                 "$XENBUS_PATH/hotplug-status" busy
  log err "$@"
  exit 1
}


##
# Print the given device's major and minor numbers, written in hex and
# separated by a colon.
device_major_minor()
{
  stat -L -c %t:%T "$1"
}


##
# Write physical-device = MM,mm to the store, where MM and mm are the major 
# and minor numbers of device respectively.
#
# @param device The device from which major and minor numbers are read, which
#               will be written into the store.
#
write_dev() {
  local mm
  
  mm=$(device_major_minor "$1")
 
  if [ -z $mm ]
  then
    fatal "Backend device does not exist"
  fi
 
  xenstore_write "$XENBUS_PATH/physical-device" "$mm"
  xenstore_write "$XENBUS_PATH/physical-device-path" "$1"
  
  success
}


##
# canonicalise_mode mode
#
# Takes the given mode, which may be r, w, ro, rw, w!, or rw!, or variations
# thereof, and canonicalises them to one of
#
#   'r': perform checks for a new read-only mount;
#   'w': perform checks for a read-write mount; or
#   '!': perform no checks at all.
#
canonicalise_mode()
{
  local mode="$1"

  if ! expr index "$mode" 'w' >/dev/null
  then
    echo 'r'
  elif ! expr index "$mode" '!' >/dev/null
  then
    echo 'w'
  else
    echo '!'
  fi
}


same_vm()
{
  local otherdom="$1"
  # Note that othervm can be MISSING here, because Xend will be racing with
  # the hotplug scripts -- the entries in /local/domain can be removed by
  # Xend before the hotplug scripts have removed the entry in
  # /local/domain/0/backend/.  In this case, we want to pretend that the
  # VM is the same as FRONTEND_UUID, because that way the 'sharing' will be
  # allowed.
  local othervm=$(xenstore_read_default "/local/domain/$otherdom/vm"         \
                  "$FRONTEND_UUID")
  local target=$(xenstore_read_default  "/local/domain/$FRONTEND_ID/target"   \
                 "-1")
  local targetvm=$(xenstore_read_default "/local/domain/$target/vm" "-1")
  local otarget=$(xenstore_read_default  "/local/domain/$otherdom/target"   \
                 "-1")
  local otvm=$(xenstore_read_default  "/local/domain/$otarget/vm"   \
                 "-1")
  otvm=${otvm%-1}
  othervm=${othervm%-1}
  targetvm=${targetvm%-1}
  local frontend_uuid=${FRONTEND_UUID%-1}
  
  [ "$frontend_uuid" = "$othervm" -o "$targetvm" = "$othervm" -o \
    "$frontend_uuid" = "$otvm" -o "$targetvm" = "$otvm" ]
}

