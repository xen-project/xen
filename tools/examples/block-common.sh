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
  xenstore_write "$XENBUS_PATH/hotplug-status" busy
  xenstore_write "$XENBUS_PATH/hotplug-error" "$*"
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

  success
}
