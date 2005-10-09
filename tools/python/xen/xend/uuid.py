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
    return commands.getoutput(cmd)


def getUuidRandom():
    """Generate a random UUID."""
    
    bytes = [ random.randint(0, 255) for i in range(0, 16) ]
    # Encode the variant.
    bytes[6] = (bytes[6] & 0x0f) | 0x40
    bytes[8] = (bytes[8] & 0x3f) | 0x80
    f = "%02x"
    return ( "-".join([f*4, f*2, f*2, f*2, f*6]) % tuple(bytes) )


#uuidFactory = getUuidUuidgen
uuidFactory = getUuidRandom


def getUuid():
    return uuidFactory()
