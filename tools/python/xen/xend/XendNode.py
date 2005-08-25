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

"""Handler for node operations.
 Has some persistent state:
 - logs
 - notification urls

"""

import os
import xen.lowlevel.xc

class XendNode:

    def __init__(self):
        self.xc = xen.lowlevel.xc.new()

    def shutdown(self):
        return 0

    def reboot(self):
        return 0

    def notify(self, uri):
        return 0
    
    def cpu_bvt_slice_set(self, ctx_allow):
        return self.xc.bvtsched_global_set(ctx_allow=ctx_allow)

    def cpu_bvt_slice_get(self):
        return self.xc.bvtsched_global_get()
    
    def info(self):
        return self.nodeinfo() + self.physinfo()

    def nodeinfo(self):
        (sys, host, rel, ver, mch) = os.uname()
        return [['system',  sys],
                ['host',    host],
                ['release', rel],
                ['version', ver],
                ['machine', mch]]

    def physinfo(self):
        pinfo = self.xc.physinfo()
        info = [['cores_per_socket', pinfo['cores_per_socket']],
                ['threads_per_core', pinfo['threads_per_core']],
                ['cpu_mhz', pinfo['cpu_khz']/1000],
                ['memory', pinfo['total_pages']/256],
                ['free_memory', pinfo['free_pages']/256]]
        return info
        
        

def instance():
    global inst
    try:
        inst
    except:
        inst = XendNode()
    return inst

