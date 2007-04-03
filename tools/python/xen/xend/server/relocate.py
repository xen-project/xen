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

import re
import sys
import StringIO

from xen.web import protocol, tcp, unix

from xen.xend import sxp
from xen.xend import XendDomain
from xen.xend import XendOptions
from xen.xend.XendError import XendError
from xen.xend.XendLogging import log


class RelocationProtocol(protocol.Protocol):
    """Asynchronous handler for a connected relocation socket.
    """

    def __init__(self):
        protocol.Protocol.__init__(self)
        self.parser = sxp.Parser()

    def dataReceived(self, data):
        try:
            self.parser.input(data)
            while(self.parser.ready()):
                val = self.parser.get_val()
                res = self.dispatch(val)
                self.send_result(res)
            if self.parser.at_eof():
                self.close()
        except SystemExit:
            raise
        except:
            self.send_error()

    def close(self):
        if self.transport:
            self.transport.close()

    def send_reply(self, sxpr):
        io = StringIO.StringIO()
        sxp.show(sxpr, out=io)
        print >> io
        io.seek(0)
        if self.transport:
            return self.transport.write(io.getvalue())
        else:
            return 0

    def send_result(self, res):
        if res is None:
            resp = ['ok']
        else:
            resp = ['ok', res]
        return self.send_reply(resp)

    def send_error(self):
        (extype, exval) = sys.exc_info()[:2]
        return self.send_reply(['err',
                                ['type', str(extype)],
                                ['value', str(exval)]])

    def opname(self, name):
         return 'op_' + name.replace('.', '_')

    def operror(self, name, _):
        raise XendError('Invalid operation: ' +name)

    def dispatch(self, req):
        op_name = sxp.name(req)
        op_method_name = self.opname(op_name)
        op_method = getattr(self, op_method_name, self.operror)
        return op_method(op_name, req)

    def op_help(self, _1, _2):
        def nameop(x):
            if x.startswith('op_'):
                return x[3:].replace('_', '.')
            else:
                return x
        
        l = [ nameop(k) for k in dir(self) if k.startswith('op_') ]
        return l

    def op_quit(self, _1, _2):
        self.close()

    def op_receive(self, name, _):
        if self.transport:
            self.send_reply(["ready", name])
            try:
                XendDomain.instance().domain_restore_fd(
                    self.transport.sock.fileno())
            except:
                self.send_error()
                self.close()
        else:
            log.error(name + ": no transport")
            raise XendError(name + ": no transport")


def listenRelocation():
    xoptions = XendOptions.instance()
    if xoptions.get_xend_unix_server():
        path = '/var/lib/xend/relocation-socket'
        unix.UnixListener(path, RelocationProtocol)
    if xoptions.get_xend_relocation_server():
        port = xoptions.get_xend_relocation_port()
        interface = xoptions.get_xend_relocation_address()

        hosts_allow = xoptions.get_xend_relocation_hosts_allow()
        if hosts_allow == '':
            hosts_allow = None
        else:
            hosts_allow = map(re.compile, hosts_allow.split(" "))

        tcp.TCPListener(RelocationProtocol, port, interface = interface,
                        hosts_allow = hosts_allow)
