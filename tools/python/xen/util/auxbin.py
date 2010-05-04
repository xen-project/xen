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


import os
import os.path
import sys
from xen.util.path import *

def execute(exe, args = None):
    exepath = pathTo(exe)
    a = [ exepath ]
    if args:
        a.extend(args)
    try:
        os.execv(exepath, a)
    except (OSError, TypeError), exn:
        print exepath, ": ", exn
        sys.exit(1)

SEARCHDIRS = [ BINDIR, SBINDIR, LIBEXEC, PRIVATE_BINDIR, XENFIRMWAREDIR ]
def pathTo(exebin):
    for dir in SEARCHDIRS:
        exe = os.path.join(dir, exebin)
        if os.path.exists(exe):
            return exe
    return None

def xen_configdir():
    return XEN_CONFIG_DIR

def scripts_dir():
    return XEN_SCRIPT_DIR
