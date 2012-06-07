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
import commands

_xend_autorestart = {
    "NetBSD": True,
    "Linux": True,
    "SunOS": False,
}

_vif_script = {
    "SunOS": "vif-vnic"
}

_tapif_script = {
    "Linux": "no",
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

def _netbsd_balloon_stat(label):
    """Returns the value for the named label, or None if an error occurs."""

    import commands

    xend2netbsd_labels = { 'current'      : 'kern.xen.balloon.current',
                           'target'       : 'kern.xen.balloon.target',
                           'low-balloon'  : None,
                           'high-balloon' : None,
                           'limit'        : None }

    cmdarg = xend2netbsd_labels[label]
    if cmdarg is None:
        return None
    cmd = "/sbin/sysctl " + cmdarg
    sysctloutput = commands.getoutput(cmd)
    (name, value) = sysctloutput.split('=')
    return int(value)

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
    "SunOS": _solaris_balloon_stat,
    "NetBSD": _netbsd_balloon_stat,
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

def _solaris_get_cpuinfo():
    cpuinfo = {}

    # call kstat to extrace specific cpu_info output
    cmd = "/usr/bin/kstat -p -c misc -m cpu_info"
    kstatoutput = commands.getoutput (cmd)

    # walk each line
    for kstatline in kstatoutput.split('\n'):

        # split the line on 
        # module:cpu #:module#:name value
        (module, cpunum, combo, namevalue) = kstatline.split (":")

        # check to see if this cpunum is already a key.  If not,
        # initialize an empty hash table
        if not cpuinfo.has_key (int(cpunum)):
            cpuinfo[int(cpunum)] = {}

        # split the namevalue output on whitespace
        data = namevalue.split()

        # the key will be data[0]
        key = data[0]

        # check the length of the data list.  If it's larger than
        # 2, join the rest of the list together with a space.
        # Otherwise, value is just data[1]
        if len (data) > 2:
            value = ' '.join (data[1:])
        else:
            value = data[1]

        # add this key/value pair to the cpuhash
        cpuinfo[int(cpunum)][key] = value
    
    # Translate Solaris tokens into what Xend expects
    for key in cpuinfo.keys():
        cpuinfo[key]["flags"] = ""
        cpuinfo[key]["model name"] = cpuinfo[key]["brand"]
        cpuinfo[key]["cpu MHz"] = cpuinfo[key]["clock_MHz"]

    # return the hash table
    return cpuinfo

def _netbsd_get_cpuinfo():
    import commands
    cpuinfo = {}

    cmd = "/sbin/sysctl hw.ncpu"
    sysctloutput = commands.getoutput(cmd)
    (name, ncpu) = sysctloutput.split('=')

    for i in range(int(ncpu)):
        if not cpuinfo.has_key(i):
            cpuinfo[i] = {}

    # Translate NetBSD tokens into what xend expects
    for key in cpuinfo.keys():
        cpuinfo[key]['flags'] = "" 
        cpuinfo[key]['vendor_id'] = ""
        cpuinfo[key]['model name'] = ""
        cpuinfo[key]['stepping'] = ""
        cpuinfo[key]['cpu MHz'] = 0
 
    return cpuinfo


_get_cpuinfo = {
    "SunOS": _solaris_get_cpuinfo,
    "NetBSD": _netbsd_get_cpuinfo
}

def _default_prefork(name):
    pass

def _default_postfork(ct, abandon=False):
    pass

# call this for long-running processes that should survive a xend
# restart
def _solaris_prefork(name):
    from xen.lowlevel import process
    return process.activate(name)

def _solaris_postfork(ct, abandon=False):
    from xen.lowlevel import process
    process.clear(ct)
    if abandon:
        process.abandon_latest()

_get_prefork = {
    "SunOS": _solaris_prefork
}

_get_postfork = {
    "SunOS": _solaris_postfork
}

def _get(var, default=None):
    return var.get(os.uname()[0], default)

xend_autorestart = _get(_xend_autorestart)
vif_script = _get(_vif_script, "vif-bridge")
tapif_script = _get(_tapif_script)
lookup_balloon_stat = _get(_balloon_stat, _linux_balloon_stat)
get_cpuinfo = _get(_get_cpuinfo, _linux_get_cpuinfo)
prefork = _get(_get_prefork, _default_prefork)
postfork = _get(_get_postfork, _default_postfork)
