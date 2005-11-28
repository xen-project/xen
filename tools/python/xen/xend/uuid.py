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
# Copyright (C) 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 XenSource Ltd
#============================================================================


"""Universal(ly) Unique Identifiers (UUIDs).
"""


import commands
import random


def getUuidUuidgen(random = True):
    """Generate a UUID using the command uuidgen.

    If random is true (default) generates a random uuid.
    If random is false generates a time-based uuid.
    """
    cmd = "uuidgen"
    if random:
        cmd += " -r"
    else:
        cmd += " -t"
    return fromString(commands.getoutput(cmd))


def getUuidRandom():
    """Generate a random UUID."""
    
    return [ random.randint(0, 255) for i in range(0, 16) ]


#uuidFactory = getUuidUuidgen
uuidFactory = getUuidRandom


def create():
    return uuidFactory()


def toString(u):
    return "-".join(["%02x" * 4] * 4) % tuple(u)

def fromString(s):
    s = s.replace('-', '')
    return [ int(s[i : i + 2], 16) for i in range(0, 32, 2) ]
