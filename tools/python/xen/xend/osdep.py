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
    "NetBSD": True,
    "Linux": True,
    "SunOS": False,
}

_pygrub_path = {
    "SunOS": "/usr/lib/xen/bin/pygrub"
}

_vif_script = {
    "SunOS": "vif-vnic"
}

PROC_XEN_BALLOON = '/proc/xen/balloon'
SYSFS_XEN_MEMORY = '/sys/devices/system/xen_memory/xen_memory0'

def _linux_balloon_stat_proc(label):
    """Returns the value for the named label, or None if an error occurs."""

    xend2linux_labels = { 'current'      : 'Current allocation',
                          'target'       : 'Requested target',
                          'low-balloon'  : 'Low-mem balloon',
                          'high-balloon' : 'High-mem balloon',
                          'limit'        : 'Xen hard limit' }

    f = file(PROC_XEN_BALLOON, 'r')
    try:
        for line in f:
            keyvalue = line.split(':')
            if keyvalue[0] == xend2linux_labels[label]:
                values = keyvalue[1].split()
                if values[0].isdigit():
                    return int(values[0])
                else:
                    return None
        return None
    finally:
        f.close()

def _linux_balloon_stat_sysfs(label):
    sysfiles = { 'target'       : 'target_kb',
                 'current'      : 'info/current_kb',
                 'low-balloon'  : 'info/low_kb',
                 'high-balloon' : 'info/high_kb',
                 'limit'        : 'info/hard_limit_kb' }

    name = os.path.join(SYSFS_XEN_MEMORY, sysfiles[label])
    f = file(name, 'r')

    val = f.read().strip()
    if val.isdigit():
        return int(val)
    return None

def _linux_balloon_stat(label):
	if os.access(PROC_XEN_BALLOON, os.F_OK):
		return _linux_balloon_stat_proc(label)
	elif os.access(SYSFS_XEN_MEMORY, os.F_OK):
		return _linux_balloon_stat_sysfs(label)

	return None

def _solaris_balloon_stat(label):
    """Returns the value for the named label, or None if an error occurs."""

    import fcntl
    import array
    DEV_XEN_BALLOON = '/dev/xen/balloon'
    BLN_IOCTL_CURRENT = 0x42410001
    BLN_IOCTL_TARGET = 0x42410002
    BLN_IOCTL_LOW = 0x42410003
    BLN_IOCTL_HIGH = 0x42410004
    BLN_IOCTL_LIMIT = 0x42410005
    label_to_ioctl = { 'current'      : BLN_IOCTL_CURRENT,
                       'target'       : BLN_IOCTL_TARGET,
                       'low-balloon'  : BLN_IOCTL_LOW,
                       'high-balloon' : BLN_IOCTL_HIGH,
                       'limit'        : BLN_IOCTL_LIMIT }

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

def _linux_get_cpuinfo():
    cpuinfo = {}
    f = file('/proc/cpuinfo', 'r')
    try:    
        p = -1  
        d = {}  
        for line in f:
            keyvalue = line.split(':')
            if len(keyvalue) != 2:
                continue 
            key = keyvalue[0].strip()
            val = keyvalue[1].strip()
            if key == 'processor':
                if p != -1:
                    cpuinfo[p] = d
                p = int(val)
                d = {}
            else:
                d[key] = val
        cpuinfo[p] = d
        return cpuinfo
    finally:
        f.close()

_get_cpuinfo = {
}

def _get(var, default=None):
    return var.get(os.uname()[0], default)

scripts_dir = _get(_scripts_dir, "/etc/xen/scripts")
xend_autorestart = _get(_xend_autorestart)
pygrub_path = _get(_pygrub_path, "/usr/bin/pygrub")
vif_script = _get(_vif_script, "vif-bridge")
lookup_balloon_stat = _get(_balloon_stat, _linux_balloon_stat)
get_cpuinfo = _get(_get_cpuinfo, _linux_get_cpuinfo)
