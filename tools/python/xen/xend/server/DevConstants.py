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
# Copyright (C) 2005 XenSource Ltd
#============================================================================

from xen.xend import XendOptions

xoptions = XendOptions.instance()

DEVICE_CREATE_TIMEOUT  = xoptions.get_device_create_timeout();
DEVICE_DESTROY_TIMEOUT = xoptions.get_device_destroy_timeout();
HOTPLUG_STATUS_NODE = "hotplug-status"
HOTPLUG_ERROR_NODE  = "hotplug-error"
HOTPLUG_STATUS_ERROR = "error"
HOTPLUG_STATUS_BUSY  = "busy"

Connected    = 1
Error        = 2
Missing      = 3
Timeout      = 4
Busy         = 5
Disconnected = 6

xenbusState = {
    'Unknown'       : 0,
    'Initialising'  : 1,
    'InitWait'      : 2,
    'Initialised'   : 3,
    'Connected'     : 4,
    'Closing'       : 5,
    'Closed'        : 6,
    'Reconfiguring' : 7,
    'Reconfigured'  : 8,
    }
xenbusState.update(dict(zip(xenbusState.values(), xenbusState.keys())))

