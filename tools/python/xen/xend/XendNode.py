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

    def notify(self, _):
        return 0
    
    def cpu_bvt_slice_set(self, ctx_allow):
        return self.xc.bvtsched_global_set(ctx_allow=ctx_allow)

    def cpu_bvt_slice_get(self):
        return self.xc.bvtsched_global_get()
    
    def info(self):
        return self.nodeinfo() + self.physinfo() + self.xeninfo()

    def nodeinfo(self):
        (sys, host, rel, ver, mch) = os.uname()
        return [['system',  sys],
                ['host',    host],
                ['release', rel],
                ['version', ver],
                ['machine', mch]]

    def physinfo(self):
        pinfo = self.xc.physinfo()
        info = [['nr_cpus',          pinfo['nr_nodes']*pinfo['sockets_per_node']*pinfo['cores_per_socket']*pinfo['threads_per_core']],
                ['nr_nodes',         pinfo['nr_nodes']],
                ['sockets_per_node', pinfo['sockets_per_node']],
                ['cores_per_socket', pinfo['cores_per_socket']],
                ['threads_per_core', pinfo['threads_per_core']],
                ['cpu_mhz',          pinfo['cpu_khz']/1000],
                ['hw_caps',          pinfo['hw_caps']],
                ['memory',           pinfo['total_pages']/256],
                ['free_memory',      pinfo['free_pages']/256]]
        return info
        
    def xeninfo(self):
        xinfo = self.xc.xeninfo()
        return [['xen_major', xinfo['xen_major']],
                ['xen_minor', xinfo['xen_minor']],
                ['xen_extra', xinfo['xen_extra']],
                ['xen_caps',  xinfo['xen_caps']],
                ['platform_params',xinfo['platform_params']],
                ['xen_changeset', xinfo['xen_changeset']],
                ['cc_compiler', xinfo['cc_compiler']],
                ['cc_compile_by', xinfo['cc_compile_by']],
                ['cc_compile_domain', xinfo['cc_compile_domain']],
                ['cc_compile_date', xinfo['cc_compile_date']]]

def instance():
    global inst
    try:
        inst
    except:
        inst = XendNode()
    return inst

