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

command="$1"

if [ "$command" != "bind" ] && [ "$command" != "unbind" ]
then
  log err "Invalid command: $command"
  exit 1
fi


XENBUS_PATH="${XENBUS_PATH:?}"


##
# Write physical-device = 0xMMmm and node = device to the store, where MM
# and mm are the major and minor numbers of device.
#
# @param device The device from which major and minor numbers are read, which
#               will be written into the store.
#
write_dev() {
  local major
  local minor
  local pdev
  
  major=$(stat -L -c %t "$1")
  minor=$(stat -L -c %T "$1")
 
  if [ -z $major  -o -z $minor ]; then
    fatal "Backend device does not exist"
  fi
 
  pdev=$(printf "0x%02x%02x" "0x$major" "0x$minor")
  xenstore_write "$XENBUS_PATH"/physical-device "$pdev" \
                 "$XENBUS_PATH"/node "$1"

  success
}
