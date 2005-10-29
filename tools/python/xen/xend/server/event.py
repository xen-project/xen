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

import sys
import StringIO

from xen.web import protocol, tcp, unix

from xen.xend import scheduler
from xen.xend import sxp
from xen.xend import PrettyPrint
from xen.xend.XendError import XendError
from xen.xend import XendLogging
from xen.xend import XendRoot


xroot = XendRoot.instance()


DEBUG = 0

class EventProtocol(protocol.Protocol):
    """Asynchronous handler for a connected event socket.
    """

    def __init__(self, daemon):
        #protocol.Protocol.__init__(self)
        self.daemon = daemon
        # Event queue.
        self.queue = []
        self.parser = sxp.Parser()
        self.pretty = 1

    def dataReceived(self, data):
        try:
            self.parser.input(data)
            while(self.parser.ready()):
                val = self.parser.get_val()
                res = self.dispatch(val)
                self.send_result(res)
            if self.parser.at_eof():
                self.loseConnection()
        except SystemExit:
            raise
        except:
            self.send_error()

    def loseConnection(self):
        if self.transport:
            self.transport.loseConnection()
        if self.connected:
            scheduler.now(self.connectionLost)

    def connectionLost(self, reason=None):
        pass

    def send_reply(self, sxpr):
        io = StringIO.StringIO()
        if self.pretty:
            PrettyPrint.prettyprint(sxpr, out=io)
        else:
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

    def send_event(self, val):
        return self.send_reply(['event', val[0], val[1]])

    def queue_event(self, name, v):
        # Despite the name we don't queue the event here.
        # We send it because the transport will queue it.
        self.send_event([name, v])
        
    def opname(self, name):
         return 'op_' + name.replace('.', '_')

    def operror(self, name, req):
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
        self.loseConnection()

    def op_exit(self, _1, _2):
        sys.exit(0)

    def op_pretty(self, _1, _2):
        self.pretty = 1

    def op_info(self, _1, _2):
        val = ['info']
        #val += self.daemon.blkifs()
        #val += self.daemon.netifs()
        #val += self.daemon.usbifs()
        return val

    def op_trace(self, _, v):
        mode = (v[1] == 'on')
        self.daemon.tracing(mode)

    def op_log_stderr(self, _, v):
        mode = v[1]
        if mode == 'on':
            XendLogging.addLogStderr()
        else:
            XendLogging.removeLogStderr()

    def op_domain_ls(self, _1, _2):
        xd = xroot.get_component("xen.xend.XendDomain")
        return xd.list_names()

    def op_domain_configure(self, _, v):
        domid = sxp.child_value(v, "dom")
        config = sxp.child_value(v, "config")
        if domid is None:
            raise XendError("missing domain id")
        if config is None:
            raise XendError("missing domain config")
        xd = xroot.get_component("xen.xend.XendDomain")
        xd.domain_configure(domid, config)

    def op_domain_unpause(self, _, v):
        domid = sxp.child_value(v, "dom")
        if domid is None:
            raise XendError("missing domain id")
        xd = xroot.get_component("xen.xend.XendDomain")
        xd.domain_unpause(domid)

class EventFactory(protocol.ServerFactory):
    """Asynchronous handler for the event server socket.
    """

    def __init__(self, daemon):
        protocol.ServerFactory.__init__(self)
        self.daemon = daemon

    def buildProtocol(self, _):
        return EventProtocol(self.daemon)

def listenEvent(daemon):
    factory = EventFactory(daemon)
    if xroot.get_xend_unix_server():
        path = '/var/lib/xend/event-socket'
        unix.listenUNIX(path, factory)
    if xroot.get_xend_http_server():
        port = xroot.get_xend_event_port()
        interface = xroot.get_xend_address()
        l = tcp.listenTCP(port, factory, interface=interface)
        l.setCloExec()
