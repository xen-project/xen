#!/usr/bin/env python
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

# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

import os

_scripts_dir = {
    "Linux": "/etc/xen/scripts",
    "SunOS": "/usr/lib/xen/scripts",
}

_xend_autorestart = {
    "Linux": True,
    "SunOS": False,
}

_pygrub_path = {
    "SunOS": "/usr/lib/xen/bin/pygrub"
}

_netback_type = {
    "SunOS": "SUNW_mac"
}

_vif_script = {
    "SunOS": "vif-vnic"
}

def _linux_balloon_stat(label):
    """Returns the value for the named label, or None if an error occurs."""

    PROC_XEN_BALLOON = '/proc/xen/balloon'
    f = file(PROC_XEN_BALLOON, 'r')
    try:
        for line in f:
            keyvalue = line.split(':')
            if keyvalue[0] == label:
                values = keyvalue[1].split()
                if values[0].isdigit():
                    return int(values[0])
                else:
                    return None
        return None
    finally:
        f.close()

def _solaris_balloon_stat(label):
    """Returns the value for the named label, or None if an error occurs."""

    import fcntl
    import array
    DEV_XEN_BALLOON = '/dev/xen/balloon'
    BLN_IOCTL_CURRENT = 0x4201
    BLN_IOCTL_TARGET = 0x4202
    BLN_IOCTL_LOW = 0x4203
    BLN_IOCTL_HIGH = 0x4204
    BLN_IOCTL_LIMIT = 0x4205
    label_to_ioctl = {	'Current allocation'	: BLN_IOCTL_CURRENT,
			'Requested target'	: BLN_IOCTL_TARGET,
			'Low-mem balloon'	: BLN_IOCTL_LOW,
			'High-mem balloon'	: BLN_IOCTL_HIGH,
			'Xen hard limit'	: BLN_IOCTL_LIMIT }

    f = file(DEV_XEN_BALLOON, 'r')
    try:
        values = array.array('L', [0])
        if fcntl.ioctl(f.fileno(), label_to_ioctl[label], values, 1) == 0:
            return values[0]
        else:
            return None
    finally:
        f.close()

_balloon_stat = {
    "SunOS": _solaris_balloon_stat
}

def _get(var, default=None):
    return var.get(os.uname()[0], default)

scripts_dir = _get(_scripts_dir, "/etc/xen/scripts")
xend_autorestart = _get(_xend_autorestart)
pygrub_path = _get(_pygrub_path, "/usr/bin/pygrub")
netback_type = _get(_netback_type, "netfront")
vif_script = _get(_vif_script, "vif-bridge")
lookup_balloon_stat = _get(_balloon_stat, _linux_balloon_stat)
