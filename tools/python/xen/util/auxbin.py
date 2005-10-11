#============================================================================
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
#============================================================================
# Copyright (C) 2005 XenSource Ltd
#============================================================================


LIB_BIN_32 = "/usr/lib/xen/bin"
LIB_BIN_64 = "/usr/lib64/xen/bin"


import os
import os.path


def execute(exe, args = None):
    exepath = pathTo(exe)
    a = [ exepath ]
    if args:
        a.extend(args)
    os.execv(exepath, a)


def pathTo(exe):
    return os.path.join(path(), exe)


def path():
    machine = os.uname()[4]
    if machine.find('64') != -1 and os.path.exists(LIB_BIN_64):
        return LIB_BIN_64
    else:
        return LIB_BIN_32
