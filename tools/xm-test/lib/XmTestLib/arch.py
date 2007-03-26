#!/usr/bin/python
"""
 arch.py - Encapsulate all logic regarding what type of hardware xen
           is running on to make adding new platforms easier.

 Copyright (C) 2006 Tony Breeds IBM Corporation

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; under version 2 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""

import os
import re
import config
import commands

from Test import *

BLOCK_ROOT_DEV = "hda"

# This isn't truly platform related but it makes the code tidier
def getRdPath():
    """Locate the full path to ramdisks needed by domUs"""
    rdpath = os.environ.get("RD_PATH")
    if not rdpath:
        rdpath = "../../ramdisk"
    rdpath = os.path.abspath(rdpath)

    return rdpath

# Begin: Intel ia32 and ia64 as well as AMD 32-bit and 64-bit processors
def ia_checkBuffer(buffer):
    return

def ia_minSafeMem():
    return 32

def ia_getDeviceModel():
    """Get the path to the device model based on
    the architecture reported in uname"""
    architecture = os.uname()[4]
    if re.search("64", architecture):
        return "/usr/lib64/xen/bin/qemu-dm"
    else:
        return "/usr/lib/xen/bin/qemu-dm"

def ia_getDefaultKernel():
    """Get the path to the default DomU kernel"""
    dom0Ver = commands.getoutput("uname -r");
    domUVer = dom0Ver.replace("xen0", "xenU");

    return "/boot/vmlinuz-" + domUVer;

ia_ParavirtDefaults = {"memory"       : 64,
                       "vcpus"        : 1,
                       "kernel"       : ia_getDefaultKernel(),
                       "root"         : "/dev/ram0",
                       "ramdisk"      : getRdPath() + "/initrd.img",
}
ia_HVMDefaults =      {"memory"       : 64,
                       "vcpus"        : 1,
                       "acpi"         : 0,
                       "disk"         : ["file:%s/disk.img,ioemu:%s,w!" %
                                         (getRdPath(), BLOCK_ROOT_DEV)],
                       "kernel"       : "/usr/lib/xen/boot/hvmloader",
                       "builder"      : "hvm",
                       "sdl"          : 0,
                       "vnc"          : 0,
                       "vncviewer"    : 0,
                       "nographic"    : 1,
                       "serial"       : "pty",
                       "device_model" : ia_getDeviceModel(),
}
# End  : Intel ia32 and ia64 as well as AMD 32-bit and 64-bit processors

# Begin: PowerPC
def ppc_checkBuffer(buffer):
    checks = [
        {"pattern" : re.compile("^\d+:mon>\s*$", re.MULTILINE),
         "message" : "domain trapped into XMON"},
    ]

    for i in range(0, len(checks)):
        check=checks[i]
        if check.get('pattern').search(buffer):
            FAIL(check.get('message'))

    return

def ppc_minSafeMem():
    return 64

def ppc_getDefaultKernel():
    """Get the path to the default DomU kernel"""
    dom0Ver = commands.getoutput("uname -r");
    domUVer = dom0Ver.replace("xen0", "xenU");

    return "/boot/vmlinux-" + domUVer;

ppc_ParavirtDefaults = {"memory"  : 64,
                        "vcpus"   : 1,
                        "kernel"  : ppc_getDefaultKernel(),
                        "root"    : "/dev/ram0",
                        "ramdisk" : getRdPath() + "/initrd.img",
                        "extra"   : "xencons=tty128 console=tty128",
}
# End  : PowerPC

"""Convert from uname specification to a more general platform."""
_uname_to_arch_map = {
    "i386"  : "x86",
    "i486"  : "x86",
    "i586"  : "x86",
    "i686"  : "x86",
    "x86_64": "x86_64",
    "ia64"  : "ia64",
    "ppc"   : "powerpc",
    "ppc64" : "powerpc",
}

# Lookup current platform.
_arch = _uname_to_arch_map.get(os.uname()[4], "Unknown")
if _arch == "x86" or _arch == "x86_64" or _arch == "ia64":
    minSafeMem = ia_minSafeMem
    getDefaultKernel = ia_getDefaultKernel
    checkBuffer = ia_checkBuffer
    if config.ENABLE_HVM_SUPPORT:
        configDefaults = ia_HVMDefaults
    else:
        configDefaults = ia_ParavirtDefaults
elif _arch == "powerpc":
    minSafeMem = ppc_minSafeMem
    getDefaultKernel = ppc_getDefaultKernel
    checkBuffer = ppc_checkBuffer
    configDefaults = ppc_ParavirtDefaults
else:
    raise ValueError, "Unknown architecture!"
