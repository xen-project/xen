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
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
#============================================================================

import os

def getenv(var, val, conv=None):
    """Get a value from the environment, with optional conversion.

    @param var  name of environment variable
    @param val  default value
    @param conv conversion function to apply to env value
    @return converted value or default
    """
    try:
        v = os.getenv(var)
        if v is None:
            v = val
        else:
            print var, '=', v
        if conv:
            v = conv(v)
    except:
        v = val
    return v

# The following parameters could be placed in a configuration file.
XEND_PID_FILE      = '/var/run/xend.pid'
XEND_TRACE_FILE    = '/var/log/xen/xend.trace'
XEND_DEBUG_LOG     = '/var/log/xen/xend-debug.log'
XEND_USER          = 'root'
XEND_DEBUG         = getenv("XEND_DEBUG",     0, conv=int)
XEND_DAEMONIZE     = getenv("XEND_DAEMONIZE", not XEND_DEBUG, conv=int)
