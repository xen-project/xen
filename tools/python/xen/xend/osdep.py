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

_scripts_dir = {
    "Linux": "/etc/xen/scripts",
    "SunOS": "/usr/lib/xen/scripts",
}

_xend_autorestart = {
    "Linux": True,
    "SunOS": False,
}

_pygrub_path = {
    "SunOS": "/usr/lib/xen/bin/pygrub"
}

_netback_type = {
    "SunOS": "SUNW_mac"
}

_vif_script = {
    "SunOS": "vif-vnic"
}

def _get(var, default=None):
    return var.get(os.uname()[0], default)

scripts_dir = _get(_scripts_dir, "/etc/xen/scripts")
xend_autorestart = _get(_xend_autorestart)
pygrub_path = _get(_pygrub_path, "/usr/bin/pygrub")
netback_type = _get(_netback_type, "netfront")
vif_script = _get(_vif_script, "vif-bridge")
