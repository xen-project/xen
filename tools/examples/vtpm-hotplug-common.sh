#
# Copyright (c) 2005 IBM Corporation
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
if [ "$command" != "online" ]  &&
   [ "$command" != "offline" ] &&
   [ "$command" != "add" ]     &&
   [ "$command" != "remove" ]
then
	log err "Invalid command: $command"
	exit 1
fi


XENBUS_PATH="${XENBUS_PATH:?}"

. "$dir/vtpm-common.sh"
