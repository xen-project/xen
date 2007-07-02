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
# Copyright (C) 2005-2006 XenSource Inc.
#============================================================================


LIB_32 = "/usr/lib"
LIB_64 = "/usr/lib64"
LIB_BIN_SUFFIX = "xen/bin"

## The architectures on which the LIB_64 directory is used.  This
# deliberately excludes ia64 and ppc64, and Solaris.
LIB_64_ARCHS = [ 'x86_64', 's390x', 'sparc64']


import os
import os.path
import sys


def execute(exe, args = None):
    exepath = pathTo(exe)
    a = [ exepath ]
    if args:
        a.extend(args)
    os.execv(exepath, a)


def pathTo(exe):
    return os.path.join(path(), exe)


def path():
    return os.path.join(libpath(), LIB_BIN_SUFFIX)


def libpath():
    machine = os.uname()[4]
    if sys.argv[0] != '-c':
        prefix = os.path.dirname(os.path.dirname(sys.argv[0]))
        path = os.path.join(prefix, os.path.basename(LIB_64))
        if machine in LIB_64_ARCHS and os.path.exists(path):
            return path
        path = os.path.join(prefix, os.path.basename(LIB_32))
        if os.path.exists(path):
            return path
    if machine in LIB_64_ARCHS and os.path.exists(LIB_64):
        return LIB_64
    else:
        return LIB_32
