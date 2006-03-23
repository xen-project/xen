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
# Copyright (C) 2006 Anthony Liguori <aliguori@us.ibm.com>
#============================================================================

from xen.xend import XendDomain, XendDomainInfo, XendNode, \
                     XendLogging, XendDmesg
from xen.util.xmlrpclib2 import UnixXMLRPCServer, TCPXMLRPCServer

from xen.xend.XendClient import XML_RPC_SOCKET

def lookup(domid):
    return XendDomain.instance().domain_lookup_by_name_or_id(domid)

def dispatch(domid, fn, args):
    info = lookup(domid)
    return getattr(info, fn)(*args)

def domain(domid):
    info = lookup(domid)
    return info.sxpr()

def domains(detail=1):
    if detail < 1:
        return XendDomain.instance().list_names()
    else:
        domains = XendDomain.instance().list_sorted()
        return map(lambda dom: dom.sxpr(), domains)

def domain_create(config):
    info = XendDomain.instance().domain_create(config)
    return info.sxpr()

def domain_restore(src):
    info = XendDomain.instance().domain_restore(src)
    return info.sxpr()    

def get_log():
    f = open(XendLogging.getLogFilename(), 'r')
    try:
        return f.read()
    finally:
        f.close()

methods = ['device_create', 'destroyDevice', 'getDeviceSxprs',
           'setMemoryTarget', 'setName', 'setVCpuCount', 'shutdown',
           'send_sysrq', 'getVCPUInfo', 'waitForDevices']

exclude = ['domain_create', 'domain_restore']

class XMLRPCServer:
    def __init__(self, use_tcp=False):
        self.ready = False
        self.use_tcp = use_tcp
        
    def run(self):
        if self.use_tcp:
            # bind to something fixed for now as we may eliminate
            # tcp support completely.
            self.server = TCPXMLRPCServer(("localhost", 8005))
        else:
            self.server = UnixXMLRPCServer(XML_RPC_SOCKET)

        # Functions in XendDomainInfo
        for name in methods:
            fn = eval("lambda domid, *args: dispatch(domid, '%s', args)"%name)
            self.server.register_function(fn, "xend.domain.%s" % name)

        # Functions in XendDomain
        inst = XendDomain.instance()
        for name in dir(inst):
            fn = getattr(inst, name)
            if name.startswith("domain_") and callable(fn):
                if name not in exclude:
                    self.server.register_function(fn, "xend.domain.%s" % name[7:])

        # Functions in XendNode and XendDmesg
        for type, lst, n in [(XendNode, ['info', 'cpu_bvt_slice_set'], 'node'),
                             (XendDmesg, ['info', 'clear'], 'node.dmesg')]:
            inst = type.instance()
            for name in lst:
                self.server.register_function(getattr(inst, name),
                                              "xend.%s.%s" % (n, name))

        # A few special cases
        self.server.register_function(domain, 'xend.domain')
        self.server.register_function(domains, 'xend.domains')
        self.server.register_function(get_log, 'xend.node.log')
        self.server.register_function(domain_create, 'xend.domain.create')
        self.server.register_function(domain_restore, 'xend.domain.restore')

        self.server.register_introspection_functions()
        self.ready = True
        self.server.serve_forever()
