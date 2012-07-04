#
# Copyright (c) 2005 XenSource Ltd.
# Copyright (c) 2007 Red Hat
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

LOCK_BASEDIR=/var/run/xen-hotplug

_setlockfd()
{
    local i
    for ((i = 0; i < ${#_lockdict}; i++))
    do [ -z "${_lockdict[$i]}" -o "${_lockdict[$i]}" = "$1" ] && break
    done
    _lockdict[$i]="$1"
    let _lockfd=200+i
}


claim_lock()
{
    mkdir -p "$LOCK_BASEDIR"
    _setlockfd $1
    eval "exec $_lockfd>>$LOCK_BASEDIR/$1"
    flock -x $_lockfd
}


release_lock()
{
    _setlockfd $1
    flock -u $_lockfd
}
