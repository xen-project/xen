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

"""Convert from uname specification to a more general platform."""
_uname_to_arch_map = {
    "i386"  : "x86",
    "i486"  : "x86",
    "i586"  : "x86",
    "i686"  : "x86",
    "x86_64": "x86_64",
    "ia64"  : "ia64",
}

_arch = _uname_to_arch_map.get(os.uname()[4], "Unknown")
if _arch == "x86":
    cpuValues = {"model_name" : "Unknown",
                 "flags"      : "Unknown"}
elif _arch == "x86_64":
    cpuValues = {"model_name" : "Unknown",
                 "flags"      : "Unknown"}
elif _arch == "ia64":
    cpuValues = {"arch"     : "Unknown",
                 "features" : "Unknown"}
else:
    raise ValueError, "Unknown architecture!"
