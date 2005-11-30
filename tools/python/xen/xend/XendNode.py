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
        self.xc = xen.lowlevel.xc.xc()

    def shutdown(self):
        return 0

    def reboot(self):
        return 0

    def notify(self, _):
        return 0
    
    def cpu_bvt_slice_set(self, ctx_allow):
        return self.xc.bvtsched_global_set(ctx_allow)

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
        info = self.xc.physinfo()

        info['nr_cpus'] = (info['nr_nodes'] *
                           info['sockets_per_node'] *
                           info['cores_per_socket'] *
                           info['threads_per_core'])
        info['cpu_mhz'] = info['cpu_khz'] / 1000

        ITEM_ORDER = ['nr_cpus',
                      'nr_nodes',
                      'sockets_per_node',
                      'cores_per_socket',
                      'threads_per_core',
                      'cpu_mhz',
                      'hw_caps',
                      'total_memory',
                      'free_memory',
                      ]

        return [[k, info[k]] for k in ITEM_ORDER]


    def xeninfo(self):
        info = self.xc.xeninfo()

        ITEM_ORDER = ['xen_major',
                      'xen_minor',
                      'xen_extra',
                      'xen_caps',
                      'platform_params',
                      'xen_changeset',
                      'cc_compiler',
                      'cc_compile_by',
                      'cc_compile_domain',
                      'cc_compile_date',
                      ]

        return [[k, info[k]] for k in ITEM_ORDER]


def instance():
    global inst
    try:
        inst
    except:
        inst = XendNode()
    return inst

