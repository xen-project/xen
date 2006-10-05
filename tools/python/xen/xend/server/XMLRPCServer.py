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
# Copyright (C) 2006 XenSource Ltd.
#============================================================================

from types import ListType
import xmlrpclib
from xen.util.xmlrpclib2 import UnixXMLRPCServer, TCPXMLRPCServer

from xen.xend import XendDomain, XendDomainInfo, XendNode
from xen.xend import XendLogging, XendDmesg
from xen.xend.XendClient import XML_RPC_SOCKET
from xen.xend.XendLogging import log
from xen.xend.XendError import XendInvalidDomain

def lookup(domid):
    info = XendDomain.instance().domain_lookup_by_name_or_id(domid)
    if not info:
        raise XendInvalidDomain(str(domid))
    return info

def dispatch(domid, fn, args):
    info = lookup(domid)
    return getattr(info, fn)(*args)

# vcpu_avail is a long and is not needed by the clients.  It's far easier
# to just remove it then to try and marshal the long.
def fixup_sxpr(sexpr):
    ret = []
    for k in sexpr:
        if type(k) is ListType:
            if len(k) != 2 or k[0] != 'vcpu_avail':
                ret.append(fixup_sxpr(k))
        else:
            ret.append(k)
    return ret

def domain(domid):
    info = lookup(domid)
    return fixup_sxpr(info.sxpr())

def domains(detail=1):
    if detail < 1:
        return XendDomain.instance().list_names()
    else:
        domains = XendDomain.instance().list_sorted()
        return map(lambda dom: fixup_sxpr(dom.sxpr()), domains)

def domain_create(config):
    info = XendDomain.instance().domain_create(config)
    return fixup_sxpr(info.sxpr())

def domain_restore(src):
    info = XendDomain.instance().domain_restore(src)
    return fixup_sxpr(info.sxpr())

def get_log():
    f = open(XendLogging.getLogFilename(), 'r')
    try:
        return f.read()
    finally:
        f.close()

methods = ['device_create', 'device_configure',
           'destroyDevice','getDeviceSxprs',
           'setMemoryTarget', 'setName', 'setVCpuCount', 'shutdown',
           'send_sysrq', 'getVCPUInfo', 'waitForDevices',
           'getRestartCount']

exclude = ['domain_create', 'domain_restore']

class XMLRPCServer:
    def __init__(self, use_tcp=False, host = "localhost", port = 8006,
                 path = XML_RPC_SOCKET):
        self.use_tcp = use_tcp
        self.port = port
        self.host = host
        self.path = path
        
        self.ready = False        
        self.running = True
        
    def run(self):
        if self.use_tcp:
            self.server = TCPXMLRPCServer((self.host, self.port),
                                          logRequests = False)
        else:
            self.server = UnixXMLRPCServer(self.path, logRequests = False)

        # Legacy deprecated xm xmlrpc api
        # --------------------------------------------------------------------

        # Functions in XendDomainInfo
        for name in methods:
            fn = eval("lambda domid, *args: dispatch(domid, '%s', args)"%name)
            self.server.register_function(fn, "xend.domain.%s" % name)

        inst = XendDomain.instance()

        for name in dir(inst):
            fn = getattr(inst, name)
            if name.startswith("domain_") and callable(fn):
                if name not in exclude:
                    self.server.register_function(fn, "xend.domain.%s" % name[7:])

        # Functions in XendNode and XendDmesg
        for type, lst, n in [(XendNode, ['info'], 'node'),
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

        # Custom runloop so we can cleanup when exiting.
        # -----------------------------------------------------------------
        try:
            self.server.socket.settimeout(1.0)
            while self.running:
                self.server.handle_request()
        finally:
            self.cleanup()

    def cleanup(self):
        log.debug("XMLRPCServer.cleanup()")

    def shutdown(self):
        self.running = False
        self.ready = False

