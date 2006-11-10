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
# Copyright (c) 2006 Xensource Inc.
#============================================================================

import os
import socket
import xen.lowlevel.xc
from xen.xend import uuid
from xen.xend.XendError import XendError
from xen.xend.XendStorageRepository import XendStorageRepository

class XendNode:
    """XendNode - Represents a Domain 0 Host."""
    
    def __init__(self):
        self.xc = xen.lowlevel.xc.xc()
        self.uuid = uuid.createString()
        self.cpus = {}
        self.name = socket.gethostname()
        self.desc = ""
        self.sr = XendStorageRepository()
        
        physinfo = self.physinfo_dict()
        cpu_count = physinfo['nr_cpus']
        cpu_features = physinfo['hw_caps']
        
        for i in range(cpu_count):
            # construct uuid by appending extra bit on the host.
            # since CPUs belong to a host.
            cpu_uuid = self.uuid + '-%04d' % i
            cpu_info = {'uuid': cpu_uuid,
                        'host': self.uuid,
                        'number': i,
                        'features': cpu_features}
            self.cpus[cpu_uuid] = cpu_info

    def shutdown(self):
        return 0

    def reboot(self):
        return 0

    def notify(self, _):
        return 0
    
    #
    # Ref validation
    #
    
    def is_valid_host(self, host_ref):
        return (host_ref == self.uuid)

    def is_valid_cpu(self, cpu_ref):
        return (cpu_ref in self.cpus)

    #
    # Storage Repo
    #

    def get_sr(self):
        return self.sr

    #
    # Host Functions
    #

    def xen_version(self):
        info = self.xc.xeninfo()
        try:
            from xen import VERSION
            return {'Xen': '%(xen_major)d.%(xen_minor)d' % info,
                    'Xend': VERSION}
        except (ImportError, AttributeError):
            return {'Xen': '%(xen_major)d.%(xen_minor)d' % info,
                    'Xend': '3.0.3'}

    def get_name(self):
        return self.name

    def set_name(self, new_name):
        self.name = new_name

    def get_description(self):
        return self.desc

    def set_description(self, new_desc):
        self.desc = new_desc

    #
    # Host CPU Functions
    #

    def get_host_cpu_by_uuid(self, host_cpu_uuid):
        if host_cpu_uuid in self.cpus:
            return host_cpu_uuid
        raise XendError('Invalid CPU UUID')

    def get_host_cpu_refs(self):
        return self.cpus.keys()

    def get_host_cpu_uuid(self, host_cpu_ref):
        if host_cpu_ref in self.cpus:
            return host_cpu_ref
        else:
            raise XendError('Invalid CPU Reference')

    def get_host_cpu_features(self, host_cpu_ref):
        try:
            return self.cpus[host_cpu_ref]['features']
        except KeyError:
            raise XendError('Invalid CPU Reference')

    def get_host_cpu_number(self, host_cpu_ref):
        try:
            return self.cpus[host_cpu_ref]['number']
        except KeyError:
            raise XendError('Invalid CPU Reference')        
            
    def get_host_cpu_load(self, host_cpu_ref):
        return 0.0

    

    #
    # Getting host information.
    #

    def info(self):
        return (self.nodeinfo() + self.physinfo() + self.xeninfo() +
                self.xendinfo())

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
        # physinfo is in KiB
        info['total_memory'] = info['total_memory'] / 1024
        info['free_memory']  = info['free_memory'] / 1024

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
                      'xen_pagesize',
                      'platform_params',
                      'xen_changeset',
                      'cc_compiler',
                      'cc_compile_by',
                      'cc_compile_domain',
                      'cc_compile_date',
                      ]

        return [[k, info[k]] for k in ITEM_ORDER]

    def xendinfo(self):
        return [['xend_config_format',  2]]

    # dictionary version of *info() functions to get rid of
    # SXPisms.
    def nodeinfo_dict(self):
        return dict(self.nodeinfo())
    def xendinfo_dict(self):
        return dict(self.xendinfo())
    def xeninfo_dict(self):
        return dict(self.xeninfo())
    def physinfo_dict(self):
        return dict(self.physinfo())
    def info_dict(self):
        return dict(self.info())
    

def instance():
    global inst
    try:
        inst
    except:
        inst = XendNode()
    return inst

